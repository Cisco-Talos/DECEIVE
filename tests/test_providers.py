import asyncio
import json
import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from deceive.models import ProviderConfig
from deceive.providers import Message, ModelResult, ProviderError, SDKProvider


@pytest.mark.asyncio
@pytest.mark.parametrize("kind,blank", [(kind, "") for kind in (
    "openai", "azure", "ollama", "gemini", "bedrock")] + [("bedrock", " \t"), ("bedrock", "\n")])
async def test_provider_mapping_without_live_services(monkeypatch, kind, blank, tmp_path):
    secret = tmp_path / "secret"
    secret.write_text("private-test-key")
    config = ProviderConfig(kind=kind, model="test-model", api_key_file=secret if kind != "bedrock" else None,
                            endpoint="https://endpoint.invalid", api_version="test-version",
                            aws_profile="configured-profile", region="eu-west-1")
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
        def converse(**kwargs):
            for message in kwargs["messages"]:
                assert all(block["text"].strip() for block in message["content"]), "Blank Bedrock text"
            assert all(block["text"].strip() for block in kwargs["system"])
            return {"output": {"message": {"content": [{"text": "output"}]}},
                    "usage": {"inputTokens": 3, "outputTokens": 2}}

        client.converse.side_effect = converse
        monkeypatch.setitem(sys.modules, "boto3", sdk)
    provider = SDKProvider(config, 2, 1)
    try:
        messages = [Message("system", "simulate"), Message("user", "input")]
        if kind == "bedrock":
            messages.insert(1, Message("system", blank))
            messages.extend([Message("assistant", blank), Message("user", "continue")])
        result = await provider.complete(messages)
        assert result.text == "output"
        assert result.usage == {"input_tokens": 3, "output_tokens": 2}
        if kind == "bedrock":
            sdk.Session.assert_called_once_with(profile_name="configured-profile", region_name="eu-west-1")
            assert session.client.call_args.args == ("bedrock-runtime",)
            assert session.client.call_args.kwargs["endpoint_url"] == "https://endpoint.invalid"
            kwargs = client.converse.call_args.kwargs
            assert kwargs["modelId"] == "test-model"
            assert kwargs["inferenceConfig"]["maxTokens"] == 2048
            assert kwargs["messages"][0]["content"] == [{"text": "input"}]
            assert [m["role"] for m in kwargs["messages"]] == ["user", "assistant", "user"]
            assert messages[-2].content == blank
            assert "no textual content" in kwargs["messages"][1]["content"][0]["text"]
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
@pytest.mark.parametrize("text,expected", [
    ("The user inspected the host. Judgement: BENIGN", "BENIGN"),
    ("The user inspected the host.\n**Judgement: BENIGN**", "BENIGN"),
    ("Summary\n## Judgement: SUSPICIOUS", "SUSPICIOUS"),
    ("Judgement: MALICIOUS\nFurther unsupported commentary", "UNKNOWN"),
    ("Judgement: NOT_SURE", "UNKNOWN"),
])
async def test_summary_accepts_final_markdown_label_without_guessing(runtime_factory, text, expected):
    runtime = await runtime_factory("ssh", model=True, analyze=True)
    runtime.test_provider.complete = AsyncMock(return_value=ModelResult(text))
    session = runtime.new_session(next(iter(runtime.listeners.values())), username="guest")
    await runtime.end_session(session)
    summaries = [json.loads(line) for line in runtime.test_stream.getvalue().splitlines()
                 if json.loads(line)["message"] == "Session summary"]
    assert len(summaries) == 1 and summaries[0]["judgement"] == expected
    assert summaries[0]["details"] == text
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
