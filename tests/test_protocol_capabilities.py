"""Bounded wire probes of the current engine, not CVE emulation acceptance."""
import asyncio
from contextlib import asynccontextmanager
import json
import ssl

from aioquic.asyncio import QuicConnectionProtocol, connect
from aioquic.h3.connection import ErrorCode, H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.errors import ErrorCodes
from h2.events import ConnectionTerminated as H2Terminated, ResponseReceived, StreamEnded
import pytest

from deceive.protocols.http import HTTPApplication


@asynccontextmanager
async def h2_client(port):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.set_alpn_protocols(["h2"])
    reader, writer = await asyncio.open_connection("127.0.0.1", port, ssl=context)
    assert writer.get_extra_info("ssl_object").selected_alpn_protocol() == "h2"
    # Only the test client bypasses outbound validation, to put malformed bytes
    # on the wire. Server validation remains enabled and unchanged.
    connection = H2Connection(H2Configuration(client_side=True, validate_outbound_headers=False,
                                               normalize_outbound_headers=False))
    connection.initiate_connection()
    writer.write(connection.data_to_send())
    await writer.drain()
    try:
        yield reader, writer, connection
    finally:
        writer.close()
        await writer.wait_closed()


def headers(method=b"GET", path=b"/"):
    return [(b":method", method), (b":scheme", b"https"),
            (b":authority", b"localhost"), (b":path", path)]


async def read_h2_until(reader, writer, connection, predicate):
    events = []
    async with asyncio.timeout(5):
        while not any(predicate(event) for event in events):
            data = await reader.read(65536)
            assert data, "Peer closed before a conclusive protocol event"
            events.extend(connection.receive_data(data))
            output = connection.data_to_send()
            if output:
                writer.write(output)
                await writer.drain()
    return events


@pytest.mark.asyncio
@pytest.mark.parametrize("method", [b"GET\r\nX-Probe: local", b"GET\nX-Probe: local", b"GET\x00local"])
async def test_h2_control_characters_are_rejected_before_asgi(runtime_factory, monkeypatch, method):
    entered = []
    original = HTTPApplication.__call__

    async def observe(self, scope, receive, send):
        if scope["type"] == "http":
            entered.append(scope)
        await original(self, scope, receive, send)

    monkeypatch.setattr(HTTPApplication, "__call__", observe)
    runtime = await runtime_factory("https", versions=["2"])
    port = next(iter(runtime.servers.values())).endpoints[0]["port"]
    async with h2_client(port) as (reader, writer, connection):
        connection.send_headers(1, headers(method), end_stream=True)
        writer.write(connection.data_to_send())
        await writer.drain()
        events = await read_h2_until(reader, writer, connection, lambda e: isinstance(e, H2Terminated))
    assert any(isinstance(e, H2Terminated) and e.error_code == ErrorCodes.PROTOCOL_ERROR for e in events)
    assert not entered
    assert "User input" not in runtime.test_stream.getvalue()
    assert not runtime.sessions


@pytest.mark.asyncio
@pytest.mark.parametrize("method,expected", [(b"pRoBe /local", "PROBE /LOCAL"),
                                             (b"GET /admin HTTP/1.1", "GET /ADMIN HTTP/1.1")])
async def test_h2_method_whitespace_reaches_profile_but_case_is_normalized(runtime_factory,
                                                                        method, expected):
    runtime = await runtime_factory("https", versions=["2"])
    port = next(iter(runtime.servers.values())).endpoints[0]["port"]
    async with h2_client(port) as (reader, writer, connection):
        connection.send_headers(1, headers(method), end_stream=True)
        writer.write(connection.data_to_send())
        await writer.drain()
        events = await read_h2_until(reader, writer, connection, lambda e: isinstance(e, StreamEnded))
    assert any(isinstance(e, ResponseReceived) and (b":status", b"200") in e.headers for e in events)
    records = [json.loads(line) for line in runtime.test_stream.getvalue().splitlines()]
    event = next(r for r in records if r["message"] == "User input")
    assert event["http_method"] == expected and event["http_version"] == "2"
    assert not runtime.sessions


@pytest.mark.asyncio
async def test_h2_bounded_resets_do_not_become_profile_commands(runtime_factory):
    runtime = await runtime_factory("https", versions=["2"])
    port = next(iter(runtime.servers.values())).endpoints[0]["port"]
    async with h2_client(port) as (reader, writer, connection):
        for stream in (1, 3, 5, 7):
            connection.send_headers(stream, headers(), end_stream=False)
            connection.reset_stream(stream)
        connection.send_headers(9, headers(path=b"/api/status"), end_stream=True)
        writer.write(connection.data_to_send())
        await writer.drain()
        await read_h2_until(reader, writer, connection,
                            lambda e: isinstance(e, StreamEnded) and e.stream_id == 9)
    records = [json.loads(line) for line in runtime.test_stream.getvalue().splitlines()]
    inputs = [r for r in records if r["message"] == "User input"]
    assert len(inputs) == 1 and inputs[0]["http_path"] == "/api/status"
    assert runtime.active_requests == runtime.active_http_requests == 0
    assert not runtime.sessions


class FINProbe(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = H3Connection(self._quic)
        self.response = asyncio.get_running_loop().create_future()
        self.ended = asyncio.get_running_loop().create_future()

    def quic_event_received(self, event):
        if isinstance(event, ConnectionTerminated) and not self.ended.done():
            self.ended.set_result(event)
        for item in self.http.handle_event(event):
            if isinstance(item, HeadersReceived) and not self.response.done():
                self.response.set_result(item)


@pytest.mark.asyncio
@pytest.mark.parametrize("announced,body", [(0, b""), (2, b"ab"), (3, b""), (3, b"ab")])
async def test_h3_standalone_fin_checks_body_length_before_profile(runtime_factory, monkeypatch,
                                                                 announced, body):
    entered = asyncio.Event()
    body_received = asyncio.Event()
    original = HTTPApplication.__call__

    async def observe(self, scope, receive, send):
        if scope["type"] == "http":
            entered.set()

        async def observed_receive():
            event = await receive()
            if event.get("body"):
                body_received.set()
            return event

        await original(self, scope, observed_receive, send)

    monkeypatch.setattr(HTTPApplication, "__call__", observe)
    runtime = await runtime_factory("https", versions=["3"], limits={"request_seconds": 2})
    port = next(e["port"] for e in next(iter(runtime.servers.values())).endpoints if e["transport"] == "udp")
    config = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
    config.verify_mode = ssl.CERT_NONE
    async with connect("127.0.0.1", port, configuration=config, create_protocol=FINProbe) as client:
        stream = client._quic.get_next_available_stream_id()
        client.http.send_headers(stream, headers(b"POST") + [(b"content-length", str(announced).encode())],
                                 end_stream=False)
        client.transmit()
        await asyncio.wait_for(entered.wait(), 5)
        if body:
            client.http.send_data(stream, body, end_stream=False)
            client.transmit()
            await asyncio.wait_for(body_received.wait(), 5)
        # Finish with zero QUIC stream bytes, not an empty HTTP/3 DATA frame.
        # Awaiting server receipt above keeps this separate from prior content.
        client._quic.send_stream_data(stream, b"", end_stream=True)
        client.transmit()
        if announced == len(body):
            response = await asyncio.wait_for(client.response, 5)
            assert (b":status", b"200") in response.headers
        else:
            event = await asyncio.wait_for(client.ended, 5)
            assert event.error_code == ErrorCode.H3_MESSAGE_ERROR
            assert not client.response.done()
    records = [json.loads(line) for line in runtime.test_stream.getvalue().splitlines()]
    inputs = [r for r in records if r["message"] == "User input"]
    if announced == len(body):
        assert len(inputs) == 1 and inputs[0]["http_version"] == "3"
    else:
        assert not inputs
    assert runtime.active_requests == 0
    assert not runtime.sessions
    await runtime.close()
    assert runtime.active_http_requests == 0
