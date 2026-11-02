from __future__ import annotations

import base64
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
from typing import TextIO


def encode(value: str | bytes) -> str:
    return base64.b64encode(value.encode() if isinstance(value, str) else value).decode("ascii")


class Telemetry:
    def __init__(self, sensor_name: str, path: Path | None = None, stream: TextIO | None = None):
        self.sensor_name = sensor_name
        self.owned = path is not None
        if path:
            path.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            self.stream = os.fdopen(fd, "a", encoding="utf-8", buffering=1)
        else:
            self.stream = stream or sys.stdout
        self.publish = None

    def emit(self, message: str, *, publish: bool = True, **extra) -> None:
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "level": "INFO", "task_name": "-", "src_ip": "-", "src_port": "-",
            "dst_ip": "-", "dst_port": "-", "sensor_name": self.sensor_name,
            "sensor_protocol": "-", "protocol_instance": "-", "message": message,
        }
        event.update(extra)
        self.stream.write(json.dumps(event, ensure_ascii=True) + "\n")
        self.stream.flush()
        if publish and self.publish:
            self.publish(event)

    def close(self) -> None:
        if self.owned:
            self.stream.close()
