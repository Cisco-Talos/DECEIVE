"""Strict model-to-runtime SSH output contract; no command or file execution."""
from __future__ import annotations

import base64
import json
import re

from pydantic import Field, StrictBool, StrictInt, StrictStr, model_validator

from deceive.interaction import Response
from deceive.models import Model


def stream_bytes(text: str, encoded: str | None) -> bytes:
    return base64.b64decode(encoded, validate=True) if encoded is not None else text.encode()


class SSHReply(Model):
    stdout: StrictStr = ""
    stderr: StrictStr = ""
    stdout_base64: StrictStr | None = None
    stderr_base64: StrictStr | None = None
    exit_status: StrictInt = Field(ge=0, le=255)
    close: StrictBool = False

    @model_validator(mode="after")
    def valid_streams(self) -> SSHReply:
        for name in ("stdout", "stderr"):
            text, encoded = getattr(self, name), getattr(self, name + "_base64")
            if encoded is not None and text:
                raise ValueError("Choose text or base64 for each SSH stream")
            stream_bytes(text, encoded)
        return self


def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("Duplicate SSH reply field")
        value[key] = item
    return value


def parse_reply(text: str) -> Response:
    payload = text.strip()
    # Some text-only models add a single JSON fence despite formatting instructions.
    # Unwrap only that envelope; stream bytes inside the object remain untouched.
    fenced = re.fullmatch(r"```(?:json)?\r?\n(.*?)\r?\n```", payload, re.DOTALL)
    if fenced:
        payload = fenced[1]
    reply = SSHReply.model_validate(json.loads(payload, object_pairs_hook=unique_object))
    return Response(body=stream_bytes(reply.stdout, reply.stdout_base64),
                    stderr=stream_bytes(reply.stderr, reply.stderr_base64),
                    exit_status=reply.exit_status, close=reply.close,
                    origin="llm", behavior="llm", model_output=text)


def transcript_reply(response: Response) -> str:
    value = {"exit_status": response.exit_status, "close": response.close}
    for name, body in (("stdout", response.body), ("stderr", response.stderr)):
        try:
            value[name] = body.decode("utf-8")
        except UnicodeDecodeError:
            value[name + "_base64"] = base64.b64encode(body).decode("ascii")
    return json.dumps(value)
