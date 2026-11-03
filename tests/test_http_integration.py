import asyncio
from base64 import b64decode
import json

import httpx
import pytest

from deceive.clients import h3_connect
from deceive.config import load_profile


@pytest.mark.asyncio
@pytest.mark.parametrize("protocol,version", [("http", "1.1"), ("https", "1.1"), ("https", "2")])
async def test_http_versions_binary_headers_and_multiplexing(runtime_factory, protocol, version):
    runtime = await runtime_factory(protocol, versions=[version])
    port = next(iter(runtime.servers.values())).endpoints[0]["port"]
    async with httpx.AsyncClient(base_url=f"{protocol}://127.0.0.1:{port}", verify=False,
                                 http1=version == "1.1", http2=version == "2", trust_env=False) as client:
        responses = await asyncio.gather(*(client.get("/download") for _ in range(4)))
        assert all(r.content == b"\x00\xff\x80A" for r in responses)
        assert all(r.http_version == {"1.1": "HTTP/1.1", "2": "HTTP/2"}[version] for r in responses)
        response = await client.get("/login")
        assert response.status_code == 302
        assert len(response.headers.get_list("set-cookie")) == 2
        head = await client.head("/")
        assert head.content == b"" and int(head.headers["content-length"]) > 0
        assert (await client.get("/missing")).status_code == 404
    records = [json.loads(line) for line in runtime.test_stream.getvalue().splitlines()]
    if version == "2":
        assert len({r["src_port"] for r in records if r["message"] == "User input"}) == 1
    output = next(r for r in records if r.get("http_path") == "/download" and r["message"] == "Deception response")
    assert b64decode(output["details"]) == b"\x00\xff\x80A"
    assert not runtime.sessions


@pytest.mark.asyncio
async def test_real_http3_concurrent_streams_and_advertisement(runtime_factory):
    runtime = await runtime_factory("https", versions=["1.1", "2", "3"])
    endpoints = next(iter(runtime.servers.values())).endpoints
    tcp = next(e["port"] for e in endpoints if e["transport"] == "tcp")
    udp = next(e["port"] for e in endpoints if e["transport"] == "udp")
    async with h3_connect(udp) as client:
        results = await asyncio.gather(*(client.request("GET", "/download") for _ in range(4)))
        assert all(r.version == "3" and r.body == b"\x00\xff\x80A" for r in results)
    async with httpx.AsyncClient(verify=False, trust_env=False) as client:
        response = await client.get(f"https://127.0.0.1:{tcp}/")
        assert f':{udp}' in response.headers["alt-svc"]


@pytest.mark.asyncio
async def test_cookie_sessions_are_private_and_client_ids_not_trusted(runtime_factory):
    profile = load_profile("demo-http")
    profile.stateful = True
    from deceive.models import Behavior
    profile.behaviors = [
        Behavior(id="set", match={"path": "/set"}, transition={"flag": "yes"}, reply={"body": "set"}),
        Behavior(id="flag", match={"path": "/flag", "state": {"flag": "yes"}}, reply={"body": "yes"}),
    ]
    runtime = await runtime_factory(profile=profile)
    port = next(iter(runtime.servers.values())).endpoints[0]["port"]
    async with httpx.AsyncClient(base_url=f"http://127.0.0.1:{port}", trust_env=False) as first:
        async with httpx.AsyncClient(base_url=f"http://127.0.0.1:{port}", trust_env=False) as second:
            initial = await first.get("/set", headers={"Cookie": "session=attacker-selected"})
            assert "attacker-selected" not in initial.headers["set-cookie"]
            assert (await first.get("/flag")).text == "yes"
            assert (await second.get("/flag")).status_code == 404
    assert len(runtime.sessions) == 2


@pytest.mark.asyncio
async def test_http3_client_round_trips_private_session_cookie(runtime_factory):
    from deceive.models import Behavior

    profile = load_profile("demo-http")
    profile.stateful = True
    profile.behaviors = [
        Behavior(id="set", match={"path": "/set"}, transition={"flag": "yes"}, reply={"body": "set"}),
        Behavior(id="flag", match={"path": "/flag", "state": {"flag": "yes"}}, reply={"body": "yes"}),
    ]
    runtime = await runtime_factory("https", profile=profile, versions=["3"])
    udp = next(e["port"] for e in next(iter(runtime.servers.values())).endpoints if e["transport"] == "udp")
    async with h3_connect(udp) as first, h3_connect(udp) as second:
        initial = await first.request("GET", "/set", headers=[(b"cookie", b"session=attacker-selected")])
        assert all(b"attacker-selected" not in v for k, v in initial.headers if k == b"set-cookie")
        assert (await first.request("GET", "/flag")).body == b"yes"
        assert (await second.request("GET", "/flag")).status == 404


@pytest.mark.asyncio
async def test_http3_cookie_path_expiry_domain_and_explicit_override(runtime_factory):
    from deceive.models import Behavior

    profile = load_profile("demo-http")
    profile.behaviors.insert(0, Behavior(id="cookies", match={"path": "/cookies"}, reply={
        "headers": [("set-cookie", "scoped=inside; Path=/scope; Secure"),
                    ("set-cookie", "regular=visible; Path=/; Secure"),
                    ("set-cookie", "expired=gone; Path=/; Max-Age=0"),
                    ("set-cookie", "foreign=wrong; Path=/; Domain=example.invalid")]}))
    runtime = await runtime_factory("https", profile=profile, versions=["3"])
    udp = next(e["port"] for e in next(iter(runtime.servers.values())).endpoints if e["transport"] == "udp")
    async with h3_connect(udp) as client:
        await client.request("GET", "/cookies")
        await client.request("GET", "/scope/check")
        await client.request("GET", "/elsewhere")
        await client.request("GET", "/manual", headers=[(b"Cookie", b"manual=1")])
    captured = {}
    for record in map(json.loads, runtime.test_stream.getvalue().splitlines()):
        if record["message"] == "User input":
            request = json.loads(b64decode(record["details"]))
            captured[record["http_path"]] = b"; ".join(b64decode(v) for k, v in request["headers"]
                                                     if b64decode(k) == b"cookie")
    assert b"scoped=inside" in captured["/scope/check"]
    assert b"regular=visible" in captured["/scope/check"]
    assert b"expired=" not in captured["/scope/check"] and b"foreign=" not in captured["/scope/check"]
    assert captured["/elsewhere"] == b"regular=visible"
    assert captured["/manual"] == b"manual=1"


@pytest.mark.asyncio
async def test_http3_closed_transport_fails_promptly(runtime_factory):
    runtime = await runtime_factory("https", versions=["3"])
    udp = next(e["port"] for e in next(iter(runtime.servers.values())).endpoints if e["transport"] == "udp")
    async with h3_connect(udp) as client:
        await client.request("GET", "/api/status")
        client.close()
        await asyncio.wait_for(client.wait_closed(), 5)
        with pytest.raises(ConnectionError, match="closed"):
            await asyncio.wait_for(client.request("GET", "/api/status"), 0.2)


@pytest.mark.asyncio
async def test_http_limits_expiry_and_certificate_persistence(runtime_factory):
    profile = load_profile("demo-http")
    profile.stateful = True
    runtime = await runtime_factory("https", profile=profile, name="tls", limits={"body_bytes": 128, "idle_seconds": 0.1})
    key = (runtime.config.data_dir / "certificates/tls.key").read_bytes()
    port = next(iter(runtime.servers.values())).endpoints[0]["port"]
    async with httpx.AsyncClient(verify=False, trust_env=False) as client:
        assert (await client.post(f"https://127.0.0.1:{port}/", content=b"x" * 129)).status_code == 413
        await client.get(f"https://127.0.0.1:{port}/")
    await asyncio.sleep(0.3)
    assert not runtime.sessions
    await runtime.close()
    again = await runtime_factory("https", name="tls")
    assert (again.config.data_dir / "certificates/tls.key").read_bytes() == key


@pytest.mark.asyncio
async def test_hybrid_model_response_is_structured_and_cannot_read_host_files(runtime_factory, tmp_path):
    from deceive.providers import ModelResult

    profile = load_profile("demo-http")
    profile.fallback = "llm"
    runtime = await runtime_factory(profile=profile, model=True)
    port = next(iter(runtime.servers.values())).endpoints[0]["port"]
    secret = tmp_path / "private"
    secret.write_text("REAL-HOST-SECRET")
    candidates = [json.dumps({"status": 201, "body": "created\n", "headers": [
        ["set-cookie", "one=1"], ["set-cookie", "two=2"]]}),
        json.dumps({"status": 200, "body_file": str(secret)})]

    async def complete(messages):
        return ModelResult(candidates.pop(0))

    runtime.test_provider.complete = complete
    async with httpx.AsyncClient(trust_env=False) as client:
        first = await client.post(f"http://127.0.0.1:{port}/generated", content=b"\xff\x00")
        assert first.status_code == 201 and first.content == b"created\n"
        assert first.headers.get_list("set-cookie") == ["one=1", "two=2"]
        second = await client.get(f"http://127.0.0.1:{port}/host-read")
        assert second.status_code == 502
        assert "REAL-HOST-SECRET" not in second.text + runtime.test_stream.getvalue()
