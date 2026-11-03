"""Loopback acceptance-test clients, including a real multiplexed HTTP/3 client."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
import ssl

import httpx

from aioquic.asyncio import QuicConnectionProtocol, connect
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated


@dataclass
class HTTPResult:
    status: int
    body: bytes
    headers: list[tuple[bytes, bytes]]
    version: str


class H3Client(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = H3Connection(self._quic)
        self.pending: dict[int, asyncio.Future] = {}
        self.responses: dict[int, tuple[list, bytearray]] = {}
        self.cookies = httpx.Cookies()
        self.terminated = False

    async def request(self, method: str, path: str, body: bytes = b"",
                      headers: list[tuple[bytes, bytes]] | None = None,
                      *, timeout: float = 30) -> HTTPResult:
        if self.terminated:
            raise ConnectionError("HTTP/3 connection has closed; open a new transport")
        forwarded = [(name.lower(), value) for name, value in headers or []]
        request = httpx.Request(method, "https://localhost" + path, headers=forwarded)
        self.cookies.set_cookie_header(request)
        if not any(name.lower() == b"cookie" for name, _ in forwarded):
            forwarded.extend((k.lower(), v) for k, v in request.headers.raw if k.lower() == b"cookie")
        stream = self._quic.get_next_available_stream_id()
        future = asyncio.get_running_loop().create_future()
        self.pending[stream] = future
        self.responses[stream] = ([], bytearray())
        self.http.send_headers(stream, [(b":method", method.encode()), (b":scheme", b"https"),
                                       (b":authority", b"localhost"), (b":path", path.encode())]
                               + forwarded, end_stream=not body)
        if body:
            self.http.send_data(stream, body, end_stream=True)
        self.transmit()
        try:
            result = await asyncio.wait_for(future, timeout)
            response = httpx.Response(result.status, headers=[(k, v) for k, v in result.headers
                                      if not k.startswith(b":")], request=request)
            self.cookies.extract_cookies(response)
            return result
        finally:
            self.pending.pop(stream, None)
            self.responses.pop(stream, None)

    def quic_event_received(self, event) -> None:
        if isinstance(event, ConnectionTerminated):
            self.terminated = True
            for future in self.pending.values():
                if not future.done():
                    future.set_exception(ConnectionError("HTTP/3 connection terminated"))
        for item in self.http.handle_event(event):
            if isinstance(item, (HeadersReceived, DataReceived)) and item.stream_id in self.responses:
                headers, body = self.responses[item.stream_id]
                if isinstance(item, HeadersReceived):
                    headers.extend(item.headers)
                else:
                    body.extend(item.data)
                if item.stream_ended:
                    future = self.pending[item.stream_id]
                    if not future.done():
                        status = next((int(v) for k, v in headers if k == b":status"), 0)
                        future.set_result(HTTPResult(status, bytes(body), headers, "3"))


def h3_connect(port: int):
    config = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
    # Only used for the evaluator's ephemeral loopback servers and certificates.
    config.verify_mode = ssl.CERT_NONE
    return connect("127.0.0.1", port, configuration=config, create_protocol=H3Client)
