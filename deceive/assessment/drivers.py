from __future__ import annotations

import asyncio
import base64
from contextlib import AsyncExitStack
from importlib.metadata import entry_points
import json
import time
import ssl
from typing import Protocol
import uuid

import asyncssh
import httpx

from deceive.assessment.models import ProbeAction
from deceive.clients import ShellClient, h3_connect
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
        if action.operation == 'terminal':
            return await self.terminal(endpoint, action, key)
        if action.operation == "close":
            session = self.sessions.pop(key, None)
            if session:
                session["connection"].close()
                await session["connection"].wait_closed()
            return {"version": "ssh", "facts": {"closed": True}}
        if action.operation == "authenticate":
            p = action.parameters
            password = p.get("password", endpoint.get("password", ""))
            if not isinstance(password, str) or len(password.encode()) > 4096:
                raise ValueError("SSH authentication password exceeds 4096 bytes")
            try:
                async with asyncssh.connect("127.0.0.1", port=endpoint["ports"]["tcp"]["host"],
                    username=p.get("username", endpoint.get("username", "guest")),
                    password=password, known_hosts=None, preferred_auth="password",
                    client_keys=[]):
                    authenticated = True
            except asyncssh.PermissionDenied:
                authenticated = False
            return {"version": "ssh", "facts": {"authenticated": authenticated}}
        if action.operation not in {"exec", "commands"}:
            raise ValueError("SSH operations: authenticate, exec, commands, close")
        p = action.parameters
        commands = p.get("commands", [p.get("command", "hostname")])
        continuations = p.get('continuation_prompts', [])
        if not isinstance(continuations, list) or len(continuations) > 16 or any(
            not isinstance(value, str) or not 1 <= len(value.encode()) <= 256
            for value in continuations
        ):
            raise ValueError('Supply at most 16 bounded literal continuation prompts')
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
                encoding=None, client_version='DECEIVE-assessment-' + uuid.uuid4().hex)
            session = {"connection": connection, "id": "client-" + uuid.uuid4().hex,
                       "banner": b"", "shell": None}
            if interactive:
                try:
                    session["shell"] = await ShellClient.open(connection, endpoint.get("timeout", 35),
                        continuation_prompts=tuple(value.encode() for value in continuations))
                    session["banner"] = session["shell"].banner
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
                    result = await session["shell"].run(command, endpoint.get("timeout", 35))
                    body, raw, prompt, status, stderr = (result.body, result.raw, result.prompt,
                                                       result.exit_status, result.stderr)
                    if status is not None:
                        self.sessions.pop(key, None)
                else:
                    result = await connection.run(command, check=False)
                    body, raw, prompt, status, stderr = result.stdout, result.stdout, b"", result.exit_status, result.stderr
                if len(raw) + len(stderr) > 1048576:
                    raise ValueError("SSH observation exceeds 1 MiB")
                outputs.append({"command": command, "body_base64": encode(body), "raw_base64": encode(raw),
                                "prompt_base64": encode(prompt), "stderr_base64": encode(stderr), "exit_status": status})
                if status is not None:
                    break
            return {"version": "ssh", "session_id": session["id"],
                    "body_base64": outputs[-1]["body_base64"], "facts": {
                        "outputs": outputs, "banner_base64": encode(session["banner"]),
                        "server_version": connection.get_extra_info("server_version"),
                        "client_version": connection.get_extra_info("client_version"),
                        "source_port": connection.get_extra_info("sockname")[1]}}
        finally:
            if ephemeral or key not in self.sessions:
                self.sessions.pop(key, None)
                connection.close()
                await connection.wait_closed()

    async def terminal(self, endpoint: dict, action: ProbeAction, key: tuple) -> dict:
        """Capture real terminal screens without server markers or internal state."""
        try:
            import pyte
            from deceive.terminal_client import Screen
        except ImportError:
            raise ValueError('Terminal observations require deceive[assessment]') from None
        p = action.parameters
        events = p.get('events', [])
        if not action.session or not isinstance(events, list) or len(events) > 64:
            raise ValueError('Terminal actions require a named session and at most 64 events')
        if sum(len(json.dumps(event)) for event in events) > 16384:
            raise ValueError('Terminal action exceeds input limit')
        for event in events:
            if not isinstance(event, dict) or set(event) - {'send', 'resize', 'wait'}:
                raise ValueError('Terminal events support send, resize and literal wait')
            if 'send' in event and not isinstance(event['send'], str):
                raise ValueError('Terminal send must be text')
            if 'resize' in event:
                size = event['resize']
                if not isinstance(size, list) or len(size) != 2 or not all(type(v) is int for v in size):
                    raise ValueError('Terminal resize needs [columns, rows]')
                if not 20 <= size[0] <= 240 or not 5 <= size[1] <= 100:
                    raise ValueError('Terminal resize exceeds bounds')
        for item in [p] + events:
            if 'wait' in item and (not isinstance(item['wait'], str) or not 1 <= len(item['wait']) <= 256):
                raise ValueError('Supply a bounded literal terminal wait')
        session = self.sessions.get(key)
        if session and session.get('screen') is None:
            raise ValueError('Use a distinct session for raw terminal observations')
        started = time.monotonic()
        if not session:
            connection = await asyncssh.connect('127.0.0.1', port=endpoint['ports']['tcp']['host'],
                username=p.get('username', endpoint.get('username', 'guest')),
                password=p.get('password', endpoint.get('password', '')), known_hosts=None,
                encoding=None, client_version='DECEIVE-assessment-' + uuid.uuid4().hex)
            try:
                process = await connection.create_process(term_type=p.get('term', 'xterm'),
                    term_size=(80, 24), term_modes={asyncssh.PTY_ECHO: 1, asyncssh.PTY_ONLCR: 1})
            except BaseException:
                connection.close()
                await connection.wait_closed()
                raise
            screen = Screen(80,24)
            session = {'connection': connection, 'process': process, 'screen': screen,
                       'stream': pyte.ByteStream(screen), 'id': 'client-' + uuid.uuid4().hex}
            self.sessions[key] = session
        process = session['process']
        captures = []

        async def capture(wait: str | None = None, observed: bytes = b'') -> bytes:
            raw = bytearray()
            if wait is not None:
                if not isinstance(wait, str) or not 1 <= len(wait) <= 256:
                    raise ValueError('Supply a bounded literal terminal wait')
                async with asyncio.timeout(endpoint.get('timeout', 35)):
                    while wait.encode() not in observed + raw:
                        data = await process.stdout.read(4096)
                        if not data:
                            raise asyncio.IncompleteReadError(bytes(raw), len(wait.encode()))
                        raw.extend(data)
                        if len(raw) > 1048576:
                            raise ValueError('Terminal observation exceeds 1 MiB')
            while True:
                try:
                    data = await asyncio.wait_for(process.stdout.read(4096), .05)
                except TimeoutError:
                    break
                if not data:
                    break
                raw.extend(data)
                if len(raw) > 1048576:
                    raise ValueError('Terminal observation exceeds 1 MiB')
            session['stream'].feed(bytes(raw))
            return bytes(raw)

        initial = await capture(p.get('wait'))
        if initial:
            captures.append({'raw_base64': encode(initial)})
        observed = initial
        for event in events:
            if not isinstance(event, dict) or set(event) - {'send', 'resize', 'wait'}:
                raise ValueError('Terminal events support send, resize and literal wait')
            if 'resize' in event:
                observed = b''
                size = event['resize']
                if not isinstance(size, list) or len(size) != 2 or not all(type(v) is int for v in size):
                    raise ValueError('Terminal resize needs [columns, rows]')
                cols, rows = size
                if not 20 <= cols <= 240 or not 5 <= rows <= 100:
                    raise ValueError('Terminal resize exceeds bounds')
                process.change_terminal_size(cols, rows)
                session['screen'].resize(rows, cols)
            if 'send' in event:
                observed = b''
                if not isinstance(event['send'], str):
                    raise ValueError('Terminal send must be text')
                process.stdin.write(event['send'].encode())
            raw = await capture(event.get('wait'), observed)
            observed += raw
            captures.append({'input': event, 'raw_base64': encode(raw)})
        screen = session['screen']
        return {'version':'ssh', 'session_id':session['id'], 'facts':{
            'terminal': captures, 'screen': screen.display,
            'cursor': {'row':screen.cursor.y, 'column':screen.cursor.x},
            'seconds': time.monotonic() - started,
            'source_port': session['connection'].get_extra_info('sockname')[1],
            'client_version': session['connection'].get_extra_info('client_version'),
            'exit_status': process.exit_status}}

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
        previous = None
        if version == "3" and session and session["client"].terminated:
            previous = self.sessions.pop(session_key)
            await asyncio.wait_for(previous["stack"].aclose(), 5)
            session = None
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
            session = {"stack": stack, "client": client, "id": "client-" + uuid.uuid4().hex}
            if previous:
                client.cookies = previous["client"].cookies
                session["id"] = previous["id"]
            self.sessions[session_key] = session
        try:
            if version == "3":
                result = await session["client"].request(p.get("method", "GET"), path, body, headers,
                                                         timeout=endpoint.get("timeout", 35))
                actual, data, received, status = result.version, result.body, result.headers, result.status
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
                    "facts": {"status": status, "cookies": list(session["client"].cookies.keys()),
                              "transport_reconnected": previous is not None}}
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
        except (TimeoutError, asyncio.CancelledError, ConnectionError):
            await self.registry[protocol].execute(endpoint, ProbeAction(operation="close"), key)
            raise

    async def close(self) -> None:
        await asyncio.gather(*(driver.close() for driver in self.instances), return_exceptions=True)
