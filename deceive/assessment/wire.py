"""Small loopback-only wire probes; server protocol validation remains enabled."""
from __future__ import annotations

import asyncio
import ssl

from aioquic.asyncio import QuicConnectionProtocol, connect
from aioquic.h3.connection import H3_ALPN
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import ConnectionTerminated as H2Terminated, ResponseReceived, StreamEnded

from deceive.assessment.models import ProbeAction
from deceive.clients import H3ClientConnection
from deceive.telemetry import encode


def headers(method: bytes, path: bytes) -> list:
    return [(b":method", method), (b":scheme", b"https"), (b":authority", b"localhost"), (b":path", path)]


class FINClient(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.http = H3ClientConnection(self._quic)
        self.done = asyncio.get_running_loop().create_future()
        self.received = []
        self.body = bytearray()

    def quic_event_received(self, event):
        if isinstance(event, ConnectionTerminated) and not self.done.done():
            self.done.set_result({"termination_code": event.error_code, "reason": event.reason_phrase})
        for item in self.http.handle_event(event):
            if isinstance(item, HeadersReceived):
                self.received.extend(item.headers)
            if isinstance(item, DataReceived):
                self.body.extend(item.data)
            if isinstance(item, (HeadersReceived, DataReceived)) and item.stream_ended and not self.done.done():
                self.done.set_result({"status": next(int(v) for k, v in self.received if k == b":status")})


async def wire_probe(endpoint: dict, action: ProbeAction) -> dict:
    p = action.parameters
    path = p.get("path", "/")
    if not isinstance(path, str) or not path.startswith("/") or path.startswith("//") or len(path) > 4096:
        raise ValueError("Wire probe needs a bounded target-relative path")
    method = p.get("method", "GET")
    if not isinstance(method, str) or len(method) > 1024:
        raise ValueError("Wire probe method exceeds bounds")
    if action.operation == "h3_fin":
        if "3" not in endpoint["versions"]:
            raise ValueError("Target does not expose HTTP/3")
        config = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN)
        config.verify_mode = ssl.CERT_NONE
        body = p.get("body", "").encode()
        if len(body) > 4096:
            raise ValueError("FIN probe body exceeds bounds")
        length = int(p.get("content_length", len(body)))
        if not 0 <= length <= 65536:
            raise ValueError("Invalid announced probe length")
        async with connect("127.0.0.1", endpoint["ports"]["udp"]["host"], configuration=config,
                           create_protocol=FINClient) as client:
            stream = client._quic.get_next_available_stream_id()
            client.http.send_headers(stream, headers(method.encode(), path.encode()) +
                                     [(b"content-length", str(length).encode())], end_stream=False)
            client.transmit()
            await client.ping()
            if body:
                client.http.send_data(stream, body, end_stream=False)
                client.transmit()
                await client.ping()
            client._quic.send_stream_data(stream, b"", end_stream=True)
            client.transmit()
            facts = await asyncio.wait_for(client.done, 10)
            facts.update(stream_id=stream, standalone_fin=True, announced=length, sent=len(body))
            return {"version": "3", "body_base64": encode(bytes(client.body)),
                    "headers": [(encode(k), encode(v)) for k, v in client.received], "facts": facts}
    if "2" not in endpoint["versions"]:
        raise ValueError("Target does not expose HTTP/2")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname, context.verify_mode = False, ssl.CERT_NONE
    context.set_alpn_protocols(["h2"])
    reader, writer = await asyncio.open_connection("127.0.0.1", endpoint["ports"]["tcp"]["host"], ssl=context)
    try:
        if writer.get_extra_info("ssl_object").selected_alpn_protocol() != "h2":
            raise ValueError("HTTP/2 negotiation failed")
        connection = H2Connection(H2Configuration(client_side=True, validate_outbound_headers=False,
                                                   normalize_outbound_headers=False))
        connection.initiate_connection()
        stream = 1
        if action.operation == "h2_resets":
            count = int(p.get("count", 4))
            if not 1 <= count <= 8:
                raise ValueError("Reset probes are limited to eight streams")
            for stream in range(1, count * 2, 2):
                connection.send_headers(stream, headers(b"GET", b"/"), end_stream=False)
                connection.reset_stream(stream)
            stream += 2
        connection.send_headers(stream, headers(method.encode("ascii"), path.encode("ascii")), end_stream=True)
        sent = connection.data_to_send()
        writer.write(sent)
        await writer.drain()
        events = []
        body = bytearray()
        received = []
        while not any(isinstance(e, (H2Terminated, StreamEnded)) for e in events):
            data = await asyncio.wait_for(reader.read(65536), 10)
            if not data:
                break
            batch = connection.receive_data(data)
            events.extend(batch)
            for event in batch:
                if isinstance(event, ResponseReceived):
                    received.extend(event.headers)
                if hasattr(event, "data"):
                    body.extend(event.data)
            output = connection.data_to_send()
            if output:
                writer.write(output)
                await writer.drain()
        facts = {"events": [type(e).__name__ for e in events], "stream_id": stream,
                 "wire_sent_base64": encode(sent)}
        terminated = next((e for e in events if isinstance(e, H2Terminated)), None)
        if terminated:
            facts["termination_code"] = int(terminated.error_code)
        if received:
            facts["status"] = next(int(v) for k, v in received if k == b":status")
        return {"version": "2", "body_base64": encode(bytes(body)),
                "headers": [(encode(k), encode(v)) for k, v in received], "facts": facts}
    finally:
        writer.close()
        await writer.wait_closed()
