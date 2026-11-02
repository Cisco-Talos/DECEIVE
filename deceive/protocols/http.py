from __future__ import annotations

import asyncio
from http.cookies import CookieError, SimpleCookie

from hypercorn.asyncio.tcp_server import TCPServer
from hypercorn.asyncio.udp_server import UDPServer
from hypercorn.asyncio.worker_context import WorkerContext
from hypercorn.config import Config
from hypercorn.utils import wrap_app

from deceive.interaction import Interaction
from deceive.material import tls_pair
from deceive.models import Listener
from deceive.providers import ProviderError
from deceive.runtime import CapacityError, Runtime


class HTTPApplication:
    def __init__(self, runtime: Runtime, listener: Listener):
        self.runtime = runtime
        self.listener = listener
        self.profile = runtime.profiles[listener.name]

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] == "lifespan":
            while True:
                event = await receive()
                if event["type"] == "lifespan.startup":
                    await send({"type": "lifespan.startup.complete"})
                elif event["type"] == "lifespan.shutdown":
                    await send({"type": "lifespan.shutdown.complete"})
                    return
        if scope["type"] != "http":
            return
        if scope["http_version"] not in self.listener.versions:
            await self._send(send, 505, b"HTTP version unavailable\n")
            return
        if self.runtime.active_http_requests >= self.runtime.limits.requests:
            await self._send(send, 503, b"Service busy\n")
            return
        self.runtime.active_http_requests += 1
        session = None
        try:
            async with asyncio.timeout(self.runtime.limits.request_seconds):
                body = bytearray()
                while True:
                    event = await receive()
                    if event["type"] == "http.disconnect":
                        return
                    body.extend(event.get("body", b""))
                    if len(body) > self.runtime.limits.body_bytes:
                        await self._send(send, 413, b"Request too large\n")
                        return
                    if not event.get("more_body", False):
                        break
                headers = tuple((k.lower(), v) for k, v in scope["headers"])
                if sum(len(k) + len(v) for k, v in headers) > self.runtime.limits.input_bytes:
                    await self._send(send, 431, b"Headers too large\n")
                    return
                new_cookie = False
                if self.profile.stateful:
                    cookie = SimpleCookie()
                    try:
                        cookie.load("; ".join(v.decode("latin-1") for k, v in headers if k == b"cookie"))
                    except CookieError:
                        cookie = SimpleCookie()
                    token = cookie.get(self.profile.cookie_name)
                    candidate = self.runtime.sessions.get(token.value) if token else None
                    if candidate and candidate.listener == self.listener.name and not candidate.closed:
                        session = candidate
                if session is None:
                    session = self.runtime.new_session(
                        self.listener, source=scope.get("client"), destination=scope.get("server")
                    )
                    new_cookie = self.profile.stateful
                interaction = Interaction(
                    "http", body=bytes(body), method=scope["method"], path=scope["path"],
                    raw_path=scope.get("raw_path") or scope["path"].encode(),
                    query=scope.get("query_string", b""), headers=headers,
                    http_version=scope["http_version"],
                )
                result = await self.runtime.respond(session, interaction)
                response_headers = list(result.headers)
                if new_cookie:
                    value = f"{self.profile.cookie_name}={session.id}; HttpOnly; SameSite=Lax; Path=/"
                    if self.listener.protocol == "https":
                        value += "; Secure"
                    response_headers.append((b"set-cookie", value.encode()))
                if result.close:
                    await self.runtime.end_session(session)
                await self._send(send, result.status, result.body, response_headers,
                                 head=scope["method"] == "HEAD")
        except CapacityError:
            await self._send(send, 503, b"Service busy\n")
        except TimeoutError:
            await self._send(send, 504, b"Request timed out\n")
        except (ProviderError, ValueError):
            await self._send(send, 502, b"Response unavailable\n")
        except OSError:
            pass  # Client disconnected while sending the response.
        finally:
            self.runtime.active_http_requests -= 1
            if session and not self.profile.stateful:
                await self.runtime.end_session(session)

    async def _send(self, send, status: int, body: bytes,
                    headers: list | None = None, head: bool = False) -> None:
        headers = list(headers or [])
        # The server owns framing. Never forward model-authored hop-by-hop headers.
        forbidden = {b"connection", b"transfer-encoding", b"content-length", b"keep-alive", b"upgrade"}
        headers = [(k, v) for k, v in headers if k not in forbidden]
        if not any(k == b"content-type" for k, _ in headers):
            headers.append((b"content-type", b"text/plain; charset=utf-8"))
        if status in {204, 304}:
            body = b""
        else:
            headers.append((b"content-length", str(len(body)).encode()))
        await send({"type": "http.response.start", "status": status, "headers": headers})
        await send({"type": "http.response.body", "body": b"" if head else body})


class HTTPServerHandle:
    def __init__(self, context, sockets, endpoints):
        self.context = context
        self.sockets = sockets
        self.endpoints = endpoints
        self.servers = []
        self.transports = []
        self.tasks = set()

    async def close(self) -> None:
        await self.context.terminated.set()
        for server in self.servers:
            server.close()
        for server in self.servers:
            await server.wait_closed()
        for transport in self.transports:
            transport.close()
        if self.tasks:
            done, pending = await asyncio.wait(self.tasks, timeout=2)
            for task in pending:
                task.cancel()
            await asyncio.gather(*self.tasks, return_exceptions=True)
        for sock in self.sockets:
            sock.close()


class HTTPAdapter:
    api_version = 1

    async def start(self, runtime: Runtime, listener: Listener) -> HTTPServerHandle:
        config = Config()
        host = f"[{listener.host}]" if ":" in listener.host else listener.host
        config.bind = [f"{host}:{listener.port}"] if set(listener.versions) - {"3"} else []
        config.quic_bind = []
        config.accesslog = None
        config.errorlog = None
        config.include_server_header = False
        config.include_date_header = True
        config.graceful_timeout = 2
        config.keep_alive_timeout = min(runtime.limits.idle_seconds, 30)
        config.read_timeout = runtime.limits.request_seconds
        config.h11_max_incomplete_size = runtime.limits.input_bytes
        config.h2_max_concurrent_streams = runtime.limits.requests
        config.max_app_queue_size = runtime.limits.requests
        config.backlog = runtime.limits.sessions
        config.ssl_handshake_timeout = min(runtime.limits.request_seconds, 10)
        config.alpn_protocols = [p for version, p in (("2", "h2"), ("1.1", "http/1.1"))
                                 if version in listener.versions]
        if listener.protocol == "https":
            cert, key = tls_pair(runtime.config.data_dir, listener.name,
                                 runtime.profiles[listener.name].identity.hostname,
                                 listener.cert_file, listener.key_file)
            config.certfile, config.keyfile = str(cert), str(key)
            if "3" in listener.versions:
                port = listener.quic_port if listener.quic_port is not None else listener.port
                config.quic_bind = [f"{host}:{port}"]
        # This small shim is the only use of Hypercorn's worker API. Version is
        # constrained to 0.18.x and integration tests cover startup and shutdown.
        sockets = config.create_sockets()
        all_sockets = sockets.secure_sockets + sockets.insecure_sockets + sockets.quic_sockets
        endpoints = [{"host": sock.getsockname()[0], "port": sock.getsockname()[1],
                      "transport": "udp" if sock in sockets.quic_sockets else "tcp"}
                     for sock in all_sockets]
        if sockets.quic_sockets:
            advertised = listener.advertised_port or sockets.quic_sockets[0].getsockname()[1]
            config.alt_svc_headers = [f'h3=":{advertised}"; ma=3600']
        context = WorkerContext(None)
        handle = HTTPServerHandle(context, all_sockets, endpoints)
        loop = asyncio.get_running_loop()
        application = wrap_app(HTTPApplication(runtime, listener), 16 * 1024 * 1024, "asgi")

        async def connection(reader, writer):
            if runtime.connections >= runtime.limits.sessions:
                writer.close()
                await writer.wait_closed()
                return
            runtime.connections += 1
            task = asyncio.current_task()
            handle.tasks.add(task)
            try:
                await TCPServer(application, loop, config, context, {}, reader, writer)
            finally:
                runtime.connections -= 1
                handle.tasks.discard(task)

        class BoundedUDPServer(UDPServer):
            def datagram_received(self, data, address):
                from aioquic.buffer import Buffer
                from aioquic.quic.packet import pull_quic_header

                if hasattr(self, "protocol"):
                    connections = self.protocol.connections
                    if len({id(c) for c in connections.values()}) >= runtime.limits.sessions:
                        try:
                            header = pull_quic_header(Buffer(data=data), host_cid_length=8)
                        except ValueError:
                            return
                        if header.destination_cid not in connections:
                            return
                super().datagram_received(data, address)

        try:
            for sock in sockets.secure_sockets + sockets.insecure_sockets:
                options = {}
                if sock in sockets.secure_sockets:
                    options = {"ssl": config.create_ssl_context(),
                               "ssl_handshake_timeout": config.ssl_handshake_timeout}
                server = await asyncio.start_server(connection, sock=sock,
                                                    backlog=config.backlog, **options)
                handle.servers.append(server)
            for sock in sockets.quic_sockets:
                transport, protocol = await loop.create_datagram_endpoint(
                    lambda: BoundedUDPServer(application, loop, config, context, {}), sock=sock
                )
                handle.transports.append(transport)
                task = asyncio.create_task(protocol.run())
                handle.tasks.add(task)
                task.add_done_callback(handle.tasks.discard)
            # UDPServer initializes its QUIC parser before yielding for datagrams.
            await asyncio.sleep(0)
            for task in handle.tasks:
                if task.done():
                    task.result()
            return handle
        except BaseException:
            await handle.close()
            raise
