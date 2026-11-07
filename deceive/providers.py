from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
import importlib
import os
from typing import Literal, Protocol

import httpx

from deceive.models import ProviderConfig


class ProviderError(RuntimeError):
    """Sanitized failure at an external model boundary."""


@dataclass(frozen=True)
class Message:
    role: Literal["system", "user", "assistant"]
    content: str


@dataclass(frozen=True)
class ModelResult:
    text: str
    usage: dict[str, int] = field(default_factory=dict)
    model: str = ""


class Provider(Protocol):
    async def complete(self, messages: list[Message]) -> ModelResult: ...
    async def close(self) -> None: ...


def _secret(config: ProviderConfig) -> str | None:
    from deceive.credentials import provider_environment
    if config.api_key_file:
        value = config.api_key_file.read_text().strip()
        if not value:
            raise ValueError("Configured secret file is empty")
        return value
    if config.api_key is not None:
        return config.api_key.get_secret_value()
    environment = provider_environment(config, 'native')
    if config.api_key_env:
        value = environment.get(config.api_key_env)
        if not value:
            raise ValueError(f"Set credential environment variable {config.api_key_env}")
        return value
    if config.kind != 'bedrock':
        return next(iter(environment.values()), None)
    return None


class SDKProvider:
    """Text-only SDK adapter; SDK errors never include credentials in telemetry."""

    def __init__(self, config: ProviderConfig, timeout: float, concurrency: int):
        self.config = config
        self.tasks: set[asyncio.Task] = set()
        self.slots = asyncio.Semaphore(concurrency)
        self.errors: tuple[type[BaseException], ...] = (httpx.HTTPError,)
        module_name = {
            "openai": "openai", "azure": "openai", "ollama": "ollama",
            "gemini": "google.genai", "bedrock": "boto3",
        }[config.kind]
        try:
            sdk = importlib.import_module(module_name)
        except ImportError as exc:
            extra = "openai" if config.kind == "azure" else config.kind
            raise ValueError(f"Missing provider SDK: install 'deceive[{extra}]'") from exc
        secret = _secret(config)
        if config.kind in {"openai", "azure"}:
            variable = "AZURE_OPENAI_API_KEY" if config.kind == "azure" else "OPENAI_API_KEY"
            secret = secret or os.environ.get(variable)
            if not secret:
                raise ValueError(f"Set {variable} or configure api_key_env/api_key_file")
            options = {
                "http_client": httpx.AsyncClient(verify=config.tls_verify, timeout=timeout),
                "max_retries": 0,
            }
            if secret:
                options["api_key"] = secret
            if config.kind == "azure":
                options["azure_endpoint"] = config.endpoint
                options["api_version"] = config.api_version
                self.client = sdk.AsyncAzureOpenAI(**options)
            else:
                if config.endpoint:
                    options["base_url"] = config.endpoint
                self.client = sdk.AsyncOpenAI(**options)
            self.errors += (sdk.OpenAIError,)
        elif config.kind == "ollama":
            self.client = sdk.AsyncClient(
                host=config.endpoint, timeout=timeout, verify=config.tls_verify,
                headers={"Authorization": f"Bearer {secret}"} if secret else {},
            )
            self.errors += (sdk.ResponseError,)
        elif config.kind == "gemini":
            options = {"timeout": int(timeout * 1000), "retry_options": {"attempts": 1},
                       "client_args": {"verify": config.tls_verify},
                       "async_client_args": {"verify": config.tls_verify}}
            if config.endpoint:
                options["base_url"] = config.endpoint
            self.client = sdk.Client(api_key=secret, http_options=options)
            self.errors += (sdk.errors.APIError,)
        else:
            from botocore.config import Config
            from botocore.exceptions import BotoCoreError, ClientError

            self.errors += (BotoCoreError, ClientError)
            from deceive.credentials import provider_environment
            environment = provider_environment(config, 'native')
            credential_options = {}
            if config.aws_profile is None:
                for variable, option in [('AWS_ACCESS_KEY_ID', 'aws_access_key_id'),
                                         ('AWS_SECRET_ACCESS_KEY', 'aws_secret_access_key'),
                                         ('AWS_SESSION_TOKEN', 'aws_session_token')]:
                    if variable in environment:
                        credential_options[option] = environment[variable]
            session = sdk.Session(profile_name=config.aws_profile or environment.get('AWS_PROFILE')
                                  or environment.get('AWS_DEFAULT_PROFILE'),
                                  region_name=config.region or environment.get('AWS_REGION')
                                  or environment.get('AWS_DEFAULT_REGION'), **credential_options)
            self.client = session.client(
                "bedrock-runtime", endpoint_url=config.endpoint, verify=config.tls_verify,
                config=Config(
                    connect_timeout=min(timeout, 5), read_timeout=timeout,
                    retries={"total_max_attempts": 1, "mode": "adaptive"},
                    max_pool_connections=concurrency,
                ),
            )

    async def complete(self, messages: list[Message]) -> ModelResult:
        c = self.config
        try:
            if c.kind in {"openai", "azure"}:
                options = {"model": c.model, "messages": [m.__dict__ for m in messages],
                           "max_completion_tokens": c.max_output_tokens}
                if c.temperature is not None:
                    options["temperature"] = c.temperature
                result = await self.client.chat.completions.create(**options)
                usage = result.usage
                return ModelResult(result.choices[0].message.content or "", {
                    "input_tokens": usage.prompt_tokens if usage else 0,
                    "output_tokens": usage.completion_tokens if usage else 0,
                }, c.model)
            if c.kind == "ollama":
                options = {"num_predict": c.max_output_tokens}
                if c.temperature is not None:
                    options["temperature"] = c.temperature
                result = await self.client.chat(
                    model=c.model, messages=[m.__dict__ for m in messages], options=options
                )
                return ModelResult(result.message.content, {
                    "input_tokens": result.prompt_eval_count or 0,
                    "output_tokens": result.eval_count or 0,
                }, c.model)
            if c.kind == "gemini":
                system = "\n".join(m.content for m in messages if m.role == "system")
                contents = [
                    {"role": "model" if m.role == "assistant" else "user",
                     "parts": [{"text": m.content}]} for m in messages if m.role != "system"
                ]
                options = {"system_instruction": system, "max_output_tokens": c.max_output_tokens}
                if c.temperature is not None:
                    options["temperature"] = c.temperature
                result = await self.client.aio.models.generate_content(
                    model=c.model, contents=contents, config=options
                )
                usage = result.usage_metadata
                return ModelResult(result.text or "", {
                    "input_tokens": (usage.prompt_token_count or 0) if usage else 0,
                    "output_tokens": (usage.candidates_token_count or 0) if usage else 0,
                }, c.model)
            # Keep slots occupied until the synchronous SDK call actually ends,
            # even when the waiting SSH/HTTP request has timed out or disconnected.
            await self.slots.acquire()
            task = asyncio.create_task(asyncio.to_thread(self._bedrock, messages))
            self.tasks.add(task)
            task.add_done_callback(self._thread_done)
            return await asyncio.shield(task)
        except self.errors as exc:
            raise ProviderError(f"{c.kind} request failed ({type(exc).__name__})") from None

    def _thread_done(self, task: asyncio.Task) -> None:
        self.tasks.discard(task)
        self.slots.release()
        if not task.cancelled():
            task.exception()

    def _bedrock(self, messages: list[Message]) -> ModelResult:
        c = self.config
        options = {"maxTokens": c.max_output_tokens}
        if c.temperature is not None:
            options["temperature"] = c.temperature
        system = [{"text": m.content} for m in messages if m.role == "system" and m.content.strip()]
        if any(not m.content.strip() for m in messages if m.role != "system"):
            # Converse rejects blank text blocks; keep empty turns in their original order.
            system.append({"text": "Transcript convention: (no textual content) represents a blank "
                           "turn. It is metadata, never output to reproduce."})
        result = self.client.converse(
            modelId=c.model,
            system=system,
            messages=[{"role": m.role, "content": [{"text": m.content if m.content.strip()
                                                      else "(no textual content)"}]}
                      for m in messages if m.role != "system"],
            inferenceConfig=options,
        )
        usage = result.get("usage", {})
        return ModelResult("".join(p.get("text", "") for p in result["output"]["message"]["content"]),
                           {"input_tokens": usage.get("inputTokens", 0),
                            "output_tokens": usage.get("outputTokens", 0)}, c.model)

    async def close(self) -> None:
        if self.tasks:
            await asyncio.gather(*self.tasks, return_exceptions=True)
        if self.config.kind in {"openai", "azure"}:
            await self.client.close()
        elif self.config.kind == "ollama":
            await self.client.close()
        elif self.config.kind == "gemini":
            await self.client.aio.aclose()
            self.client.close()
        else:
            await asyncio.to_thread(self.client.close)
