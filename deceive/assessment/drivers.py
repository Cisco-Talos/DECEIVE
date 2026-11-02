from __future__ import annotations

import asyncio
import base64
from contextlib import AsyncExitStack
from importlib.metadata import entry_points
from http.cookies import SimpleCookie
import json
import ssl
from typing import Protocol
import uuid

import asyncssh
import httpx

from deceive.assessment.models import ProbeAction
from deceive.clients import h3_connect
from deceive.telemetry import encode


class AssessmentDriver(Protocol):
    api_version: int
    protocols: set[str]

    def bindings(self, listener: dict) -> list[tuple[str, int]]: ...

    async def execute(self, endpoint: dict, action: ProbeAction, key: tuple) -> dict: ...
    async def close(self) -> None: ...


class SSHDriver:
    api_version = 1
    protocols = {"ssh"}

    def __init__(self):
        self.sessions = {}

    def bindings(self, listener: dict) -> list[tuple[str, int]]:
        return [("tcp", listener["port"])]

    async def execute(self, endpoint: dict, action: ProbeAction, key: tuple) -> dict:
        if action.operation == "close":
            session = self.sessions.pop(key, None)
            if session:
                session["connection"].close()
                await session["connection"].wait_closed()
            return {"version": "ssh", "facts": {"closed": True}}
        if action.operation not in {"exec", "commands"}:
            raise ValueError("SSH operations: exec, commands, close")
        p = action.parameters
        commands = p.get("commands", [p.get("command", "hostname")])
        if not isinstance(commands, list) or not 1 <= len(commands) <= 30 or not all(
            isinstance(c, str) and "\n" not in c and "\r" not in c and len(c.encode()) <= 16384
            for c in commands
        ):
            raise ValueError("Supply 1–30 bounded single-line command strings")
        interactive = bool(action.session or p.get("interactive") or len(commands) > 1)
        session = self.sessions.get(key) if interactive else None
        ephemeral = action.session is None
        if not session:
            connection = await asyncssh.connect("127.0.0.1", port=endpoint["ports"]["tcp"]["host"],
                username=p.get("username", endpoint.get("username", "guest")),
                password=p.get("password", endpoint.get("password", "")), known_hosts=None,
                encoding=None)
            session = {"connection": connection, "id": "client-" + uuid.uuid4().hex,
                       "banner": b"", "process": None}
            if interactive:
                try:
                    process = await connection.create_process(term_type="xterm")
                    session["process"] = process
                    session["banner"] = await process.stdout.readuntil((b"$ ", b"# "))
                    self.sessions[key] = session
                except BaseException:
                    connection.close()
                    await connection.wait_closed()
                    raise
        connection = session["connection"]
        outputs = []
        try:
            for command in commands:
                if interactive:
                    process = session["process"]
                    process.stdin.write(command.encode() + b"\n")
                    try:
                        raw = await process.stdout.readuntil((b"$ ", b"# "))
                        if b"\n" in raw:
                            body, prompt = raw.rsplit(b"\n", 1)
                            body += b"\n"
                        else:
                            body, prompt = b"", raw
                        status = None
                    except asyncio.IncompleteReadError as exc:
                        raw = body = exc.partial
                        prompt = b""
                        await process.wait_closed()
                        status = process.exit_status
                        self.sessions.pop(key, None)
                else:
                    result = await connection.run(command, check=False)
                    body, raw, prompt, status = result.stdout, result.stdout, b"", result.exit_status
                if len(raw) > 1048576:
                    raise ValueError("SSH observation exceeds 1 MiB")
                outputs.append({"command": command, "body_base64": encode(body), "raw_base64": encode(raw),
                                "prompt_base64": encode(prompt), "exit_status": status})
                if status is not None:
                    break
            return {"version": "ssh", "session_id": session["id"],
                    "body_base64": outputs[-1]["body_base64"], "facts": {
                        "outputs": outputs, "banner_base64": encode(session["banner"]),
                        "server_version": connection.get_extra_info("server_version"),
                        "source_port": connection.get_extra_info("sockname")[1]}}
        finally:
            if ephemeral:
                self.sessions.pop(key, None)
                connection.close()
                await connection.wait_closed()

    async def close(self) -> None:
        for session in self.sessions.values():
            session["connection"].close()
        await asyncio.gather(*(s["connection"].wait_closed() for s in self.sessions.values()),
                             return_exceptions=True)
        self.sessions.clear()


class HTTPDriver:
    api_version = 1
    protocols = {"http", "https"}

    def __init__(self):
        self.sessions = {}

    def bindings(self, listener: dict) -> list[tuple[str, int]]:
        result = [("tcp", listener["port"])] if set(listener["versions"]) - {"3"} else []
        if "3" in listener["versions"]:
            result.append(("udp", listener.get("quic_port") or listener["port"]))
        return result

    async def execute(self, endpoint: dict, action: ProbeAction, key: tuple) -> dict:
        if action.operation == "close":
            for stored in list(self.sessions):
                if stored[:len(key)] == key:
                    session = self.sessions.pop(stored)
                    await session["stack"].aclose()
            return {"facts": {"closed": True}}
        if action.operation in {"h2_method", "h2_resets", "h3_fin"}:
            from deceive.assessment.wire import wire_probe
            return await wire_probe(endpoint, action)
        if action.operation != "request":
            raise ValueError("HTTP operations: request, close, h2_method, h2_resets, h3_fin")
        p = action.parameters
        version = str(p.get("version", endpoint["versions"][0]))
        if version not in endpoint["versions"]:
            raise ValueError("Requested HTTP version is not enabled for this target")
        path = p.get("path", "/")
        if not isinstance(path, str) or not path.startswith("/") or path.startswith("//"):
            raise ValueError("Only target-relative absolute paths are accepted")
        body = base64.b64decode(p["body_base64"], validate=True) if "body_base64" in p else p.get("body", "").encode()
        if len(body) > 1048576 or len(path) > 16384:
            raise ValueError("Probe input exceeds bounds")
        headers = [(str(k).encode("ascii"), str(v).encode("latin-1")) for k, v in p.get("headers", [])]
        if sum(len(k) + len(v) for k, v in headers) > 16384:
            raise ValueError("Probe headers exceed bounds")
        session_key = key + (version,)
        session = self.sessions.get(session_key)
        if not session:
            stack = AsyncExitStack()
            if version == "3":
                client = await stack.enter_async_context(h3_connect(endpoint["ports"]["udp"]["host"]))
            else:
                port = endpoint["ports"]["tcp"]["host"]
                client = await stack.enter_async_context(httpx.AsyncClient(
                    base_url=f'{endpoint["protocol"]}://127.0.0.1:{port}', verify=False,
                    http1=version == "1.1", http2=version == "2", trust_env=False,
                    follow_redirects=False, timeout=endpoint.get("timeout", 35)))
            session = {"stack": stack, "client": client, "id": "client-" + uuid.uuid4().hex, "cookies": {}}
            self.sessions[session_key] = session
        try:
            if version == "3":
                if session["cookies"] and not any(k.lower() == b"cookie" for k, _ in headers):
                    headers.append((b"cookie", "; ".join(k + "=" + v for k, v in session["cookies"].items()).encode()))
                result = await session["client"].request(p.get("method", "GET"), path, body, headers)
                actual, data, received, status = result.version, result.body, result.headers, result.status
                for k, v in received:
                    if k.lower() == b"set-cookie":
                        cookie = SimpleCookie()
                        cookie.load(v.decode("latin-1"))
                        session["cookies"].update({k: v.value for k, v in cookie.items()})
            else:
                result = await session["client"].request(p.get("method", "GET"), path, content=body, headers=headers)
                actual = {"HTTP/1.1": "1.1", "HTTP/2": "2"}.get(result.http_version, result.http_version)
                data, received, status = result.content, list(result.headers.raw), result.status_code
            if actual != version:
                raise ValueError(f"Protocol fallback: expected {version}, got {actual}")
            if len(data) > 1048576:
                raise ValueError("HTTP observation exceeds 1 MiB")
            return {"version": actual, "session_id": session["id"], "body_base64": encode(data),
                    "headers": [(encode(k), encode(v)) for k, v in received],
                    "facts": {"status": status, "cookies": list(session["client"].cookies.keys())
                              if version != "3" else []}}
        finally:
            if action.session is None:
                self.sessions.pop(session_key, None)
                await session["stack"].aclose()

    async def close(self) -> None:
        await asyncio.gather(*(s["stack"].aclose() for s in self.sessions.values()), return_exceptions=True)
        self.sessions.clear()


class Drivers:
    def __init__(self, enabled: list[str] = ()):
        self.instances = [SSHDriver(), HTTPDriver()]
        available = {ep.name: ep for ep in entry_points(group="deceive.assessment_drivers")}
        for name in enabled:
            if name not in available:
                raise ValueError(f"Assessment driver not installed: {name}")
            instance = available[name].load()()
            if getattr(instance, "api_version", None) != 1:
                raise ValueError("Unsupported assessment driver API")
            self.instances.append(instance)
        self.registry = {}
        for instance in self.instances:
            for protocol in instance.protocols:
                if protocol in self.registry:
                    raise ValueError(f"Duplicate assessment driver for {protocol}")
                self.registry[protocol] = instance

    async def execute(self, endpoint: dict, action: ProbeAction, key: tuple) -> dict:
        protocol = endpoint["protocol"]
        if protocol not in self.registry:
            raise ValueError(f"Missing assessment driver: {protocol}")
        try:
            async with asyncio.timeout(endpoint.get("timeout", 35)):
                return await self.registry[protocol].execute(endpoint, action, key)
        except (TimeoutError, asyncio.CancelledError):
            await self.registry[protocol].execute(endpoint, ProbeAction(operation="close"), key)
            raise

    async def close(self) -> None:
        await asyncio.gather(*(driver.close() for driver in self.instances), return_exceptions=True)
