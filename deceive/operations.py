"""Versioned command results for operators and agent workflows."""
from __future__ import annotations

import argparse
from dataclasses import asdict, dataclass, field
import json


def output_argument(command: argparse.ArgumentParser) -> None:
    command.add_argument("--json", dest="json_output", action="store_true",
                         default=argparse.SUPPRESS, help="Return a versioned operation result")


@dataclass
class OperationResult:
    operation: str
    data: dict = field(default_factory=dict)
    exit_code: int = 0
    artifacts: list[str] = field(default_factory=list)
    error: dict | None = None
    schema_version: int = 1

    def as_dict(self) -> dict:
        return asdict(self) | {"ok": self.exit_code == 0,
                               "status": "succeeded" if self.exit_code == 0 else "failed"}

    def emit(self, *, json_output: bool, lines: list[str]) -> int:
        if json_output:
            print(json.dumps(self.as_dict(), indent=2))
        else:
            for line in lines:
                print(line)
        return self.exit_code
