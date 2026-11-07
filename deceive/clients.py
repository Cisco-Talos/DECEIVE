"""Loopback acceptance-test clients, including a real multiplexed HTTP/3 client."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
import ssl
import re

import asyncssh
import httpx

from aioquic.asyncio import QuicConnectionProtocol, connect
from aioquic.h3.connection import H3_ALPN, H3Connection, H3Stream, MessageError
from aioquic.h3.events import DataReceived, H3Event, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated, QuicEvent, StreamReset


@dataclass
class HTTPResult:
    status: int
    body: bytes
    headers: list[tuple[bytes, bytes]]
    version: str


@dataclass
class ShellOutput:
    body: bytes
    raw: bytes
    prompt: bytes
    exit_status: int | None
    stderr: bytes = b""


class ShellClient:
    """Public-wire interactive client with configurable device prompt recognition."""

    DEFAULT_PROMPT = rb'(?:[^\r\n]{1,128}@[A-Za-z0-9][A-Za-z0-9.-]{0,62}:[^\r\n]{0,4096}[$#] |(?:PS )?[A-Za-z]:\\[^\r\n]{0,4096}> |[A-Za-z0-9][A-Za-z0-9.-]{0,62}(?:\(config(?:-if)?\))?[>#] )'

    def __init__(self, process, banner: bytes, pattern=None):
        self.process = process
        self.banner = banner
        self.pattern = pattern or re.compile(self.DEFAULT_PROMPT)
        self.user_prefix = banner.rsplit(b'\n', 1)[-1].split(b'@', 1)[0] + b'@' if b'@' in banner.rsplit(b'\n', 1)[-1] else None

    @classmethod
    async def open(cls, connection: asyncssh.SSHClientConnection, timeout: float,
                   prompt_pattern: bytes | None = None,
                   continuation_prompts: tuple[bytes, ...] = ()) -> ShellClient:
        process = await connection.create_process(term_type="xterm")
        pattern = re.compile(prompt_pattern or cls.DEFAULT_PROMPT)
        banner = await asyncio.wait_for(process.stdout.readuntil(pattern), timeout)
        if continuation_prompts:
            pattern = re.compile(b'(?:' + pattern.pattern + b'|' +
                                 b'|'.join(re.escape(p) for p in continuation_prompts) + b')')
        return cls(process, banner, pattern)

    async def run(self, command: str, timeout: float) -> ShellOutput:
        self.process.stdin.write(command.encode() + b"\n")
        try:
            raw = await asyncio.wait_for(self.process.stdout.readuntil(self.pattern), timeout)
            # A command can print prompt-like bytes. Observe a short quiet interval and
            # select the final prompt; this is wire inference, never a server marker.
            async with asyncio.timeout(timeout):
                while True:
                    try:
                        more = await asyncio.wait_for(self.process.stdout.read(4096), .02)
                    except TimeoutError:
                        break
                    if not more:
                        break
                    raw += more
                    if len(raw) > 1048576:
                        raise ValueError('SSH observation exceeds 1 MiB')
            matches = list(self.pattern.finditer(raw))
            if not matches:
                raise ValueError('Missing device prompt')
            match = matches[-1]
            start = match.start()
            if self.user_prefix:
                known = raw.rfind(self.user_prefix)
                if known >= start:
                    start = known
            return ShellOutput(raw[:start], raw, raw[start:], None)
        except asyncio.IncompleteReadError as exc:
            await asyncio.wait_for(self.process.wait_closed(), timeout)
            stderr = await self.process.stderr.read()
            return ShellOutput(exc.partial, exc.partial, b"", self.process.exit_status, stderr)


class H3ClientConnection(H3Connection):
    """Keep HEAD representation metadata separate from response body framing."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._head_requests: set[int] = set()

    def send_headers(self, stream_id: int, headers: list[tuple[bytes, bytes]],
                     end_stream: bool = False) -> None:
        super().send_headers(stream_id, headers, end_stream=end_stream)
        if (b":method", b"HEAD") in headers:
            self._head_requests.add(stream_id)

    def _check_content_length(self, stream: H3Stream) -> None:
        # aioquic's framing hook otherwise compares HEAD's metadata length to zero
        # body bytes, closing a valid response. Retain headers and ordinary GET checks.
        if stream.stream_id in self._head_requests:
            if stream.content_length:
                raise MessageError("HEAD response cannot contain content")
            return
        super()._check_content_length(stream)

    def handle_event(self, event: QuicEvent) -> list[H3Event]:
        events = super().handle_event(event)
        for item in events:
            if isinstance(item, (HeadersReceived, DataReceived)) and item.stream_ended:
                self._head_requests.discard(item.stream_id)
        if isinstance(event, StreamReset):
            self._head_requests.discard(event.stream_id)
        elif isinstance(event, ConnectionTerminated):
            self._head_requests.clear()
        return events


class H3Client(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = H3ClientConnection(self._quic)
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
