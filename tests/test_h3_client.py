import pytest

from aioquic.h3.connection import H3Stream, MessageError
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import ConnectionTerminated, StreamReset

from deceive.clients import H3ClientConnection


def client(method: bytes) -> H3ClientConnection:
    connection = H3ClientConnection(QuicConnection(configuration=QuicConfiguration(is_client=True)))
    connection.send_headers(0, [(b":method", method), (b":scheme", b"https"),
                               (b":authority", b"localhost"), (b":path", b"/")], end_stream=True)
    return connection


def test_get_length_mismatches_and_head_content_are_still_rejected():
    stream = H3Stream(0)
    stream.expected_content_length = 12
    stream.content_length = 0
    with pytest.raises(MessageError, match="content-length"):
        client(b"GET")._check_content_length(stream)
    client(b"HEAD")._check_content_length(stream)
    stream.content_length = 12
    client(b"GET")._check_content_length(stream)
    with pytest.raises(MessageError, match="HEAD response"):
        client(b"HEAD")._check_content_length(stream)
    stream.content_length = 0
    with pytest.raises(MessageError, match="content-length"):
        client(b"head")._check_content_length(stream)


@pytest.mark.parametrize("event", [StreamReset(error_code=1, stream_id=0),
    ConnectionTerminated(error_code=0, frame_type=None, reason_phrase="closed")])
def test_head_tracking_is_released_on_reset_or_connection_end(event):
    connection = client(b"HEAD")
    assert connection._head_requests == {0}
    connection.handle_event(event)
    assert not connection._head_requests
