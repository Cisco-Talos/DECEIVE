from __future__ import annotations

from dataclasses import dataclass, field
import time
import uuid
from typing import Callable

from deceive.providers import Message


@dataclass(frozen=True)
class Interaction:
    protocol: str
    body: bytes = b""
    command: str = ""
    raw_input: bytes | None = None
    interactive: bool = False
    method: str = ""
    path: str = ""
    raw_path: bytes = b""
    query: bytes = b""
    headers: tuple[tuple[bytes, bytes], ...] = ()
    http_version: str = ""
    request_id: str = field(default_factory=lambda: f"request-{uuid.uuid4()}")


@dataclass
class Response:
    body: bytes = b""
    status: int = 200
    headers: list[tuple[bytes, bytes]] = field(default_factory=list)
    close: bool = False
    exit_status: int = 0
    behavior: str = "fallback"
    origin: str = "deterministic"
    transition: dict[str, str] = field(default_factory=dict)


@dataclass
class Session:
    id: str
    listener: str
    username: str
    context: dict
    state: dict[str, str] = field(default_factory=dict)
    history: list[Message] = field(default_factory=list)
    summary_generated: bool = False
    closed: bool = False
    started: float = field(default_factory=time.monotonic)
    touched: float = field(default_factory=time.monotonic)
    input_count: int = 0
    lock: object = None
    expire: Callable[[], None] | None = None


API_VERSION = 1
