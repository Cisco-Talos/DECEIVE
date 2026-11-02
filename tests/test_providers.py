import asyncio
import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from deceive.models import ProviderConfig
from deceive.providers import Message, ModelResult, ProviderError, SDKProvider


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["openai", "azure", "ollama", "gemini", "bedrock"])
async def test_provider_mapping_without_live_services(monkeypatch, kind, tmp_path):
    secret = tmp_path / "secret"
    secret.write_text("private-test-key")
    config = ProviderConfig(kind=kind, model="test-model", api_key_file=secret if kind != "bedrock" else None,
                            endpoint="https://endpoint.invalid", api_version="test-version")
    client = MagicMock()
    client.close = AsyncMock() if kind in {"openai", "azure"} else MagicMock()
    if kind in {"openai", "azure"}:
        sdk = SimpleNamespace(AsyncOpenAI=MagicMock(return_value=client),
                              AsyncAzureOpenAI=MagicMock(return_value=client), OpenAIError=httpx.HTTPError)
        result = SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content="output"))],
                                 usage=SimpleNamespace(prompt_tokens=3, completion_tokens=2))
        client.chat.completions.create = AsyncMock(return_value=result)
        monkeypatch.setitem(sys.modules, "openai", sdk)
    elif kind == "ollama":
        sdk = SimpleNamespace(AsyncClient=MagicMock(return_value=client), ResponseError=httpx.HTTPError)
        client.chat = AsyncMock(return_value=SimpleNamespace(message=SimpleNamespace(content="output"),
                                                            prompt_eval_count=3, eval_count=2))
        client.close = AsyncMock()
        monkeypatch.setitem(sys.modules, "ollama", sdk)
    elif kind == "gemini":
        sdk = SimpleNamespace(Client=MagicMock(return_value=client), errors=SimpleNamespace(APIError=httpx.HTTPError))
        client.aio.models.generate_content = AsyncMock(return_value=SimpleNamespace(
            text="output", usage_metadata=SimpleNamespace(prompt_token_count=3, candidates_token_count=2)))
        client.aio.aclose = AsyncMock()
        monkeypatch.setitem(sys.modules, "google.genai", sdk)
    else:
        monkeypatch.setitem(sys.modules, "botocore.config", SimpleNamespace(Config=lambda **kwargs: kwargs))
        monkeypatch.setitem(sys.modules, "botocore.exceptions", SimpleNamespace(
            BotoCoreError=type("BotoCoreError", (Exception,), {}),
            ClientError=type("ClientError", (Exception,), {})))
        session = MagicMock()
        session.client.return_value = client
        sdk = SimpleNamespace(Session=MagicMock(return_value=session))
        client.converse.return_value = {"output": {"message": {"content": [{"text": "output"}]}},
                                        "usage": {"inputTokens": 3, "outputTokens": 2}}
        monkeypatch.setitem(sys.modules, "boto3", sdk)
    provider = SDKProvider(config, 2, 1)
    try:
        result = await provider.complete([Message("system", "simulate"), Message("user", "input")])
        assert result.text == "output"
        assert result.usage == {"input_tokens": 3, "output_tokens": 2}
        if kind == "bedrock":
            kwargs = client.converse.call_args.kwargs
            assert kwargs["inferenceConfig"]["maxTokens"] == 2048
            assert kwargs["messages"][0]["content"] == [{"text": "input"}]
        elif kind in {"openai", "azure"}:
            assert client.chat.completions.create.call_args.kwargs["messages"][1]["role"] == "user"
            assert client.chat.completions.create.call_args.kwargs["max_completion_tokens"] == 2048
    finally:
        await provider.close()
        if kind in {"openai", "azure"}:
            constructor = sdk.AsyncOpenAI if kind == "openai" else sdk.AsyncAzureOpenAI
            await constructor.call_args.kwargs["http_client"].aclose()


@pytest.mark.asyncio
async def test_missing_optional_sdk_is_actionable(monkeypatch):
    import deceive.providers as module

    def missing(name):
        raise ImportError(name)

    monkeypatch.setattr(module.importlib, "import_module", missing)
    with pytest.raises(ValueError, match=r"deceive\[openai\]"):
        SDKProvider(ProviderConfig(kind="openai", model="model"), 1, 1)


@pytest.mark.asyncio
async def test_deadline_summarization_and_model_output_bound(runtime_factory):
    runtime = await runtime_factory("ssh", model=True, analyze=True,
                                    limits={"llm_seconds": 0.03, "output_bytes": 128})
    listener = next(iter(runtime.listeners.values()))
    session = runtime.new_session(listener, username="guest")

    async def delayed(messages):
        await asyncio.sleep(1)

    runtime.test_provider.complete = delayed
    await runtime.end_session(session)
    assert '"judgement": "UNKNOWN"' in runtime.test_stream.getvalue()
    assert not runtime.sessions


@pytest.mark.asyncio
@pytest.mark.parametrize("kind,package", [("openai", "openai"), ("azure", "openai"),
                                          ("ollama", "ollama"), ("gemini", "google.genai"),
                                          ("bedrock", "boto3")])
async def test_real_sdk_initialization_and_cleanup_without_network(monkeypatch, tmp_path, kind, package):
    pytest.importorskip(package)
    secret = tmp_path / "key"
    secret.write_text("test-key-never-used-for-inference")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "test-access-key")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "test-secret-key")
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    monkeypatch.delenv("AWS_DEFAULT_PROFILE", raising=False)
    config = ProviderConfig(kind=kind, model="test-model", api_key_file=secret if kind != "bedrock" else None,
                            endpoint="https://endpoint.invalid", api_version="test-version", region="us-east-1")
    provider = SDKProvider(config, 1, 1)
    await provider.close()
