import base64
from copy import deepcopy

import pytest

from deceive.assessment.telemetry import audit


def encoded(value):
    return base64.b64encode(value.encode()).decode()


def fixture():
    common = {"timestamp": "2026-11-02T00:00:00.000+00:00", "level": "INFO",
              "task_name": "session-one", "src_ip": "127.0.0.1", "src_port": 1234,
              "dst_ip": "127.0.0.1", "dst_port": 22, "sensor_protocol": "SSH",
              "sensor_name": "fixture", "profile_id": "sample"}
    records = [common | row for row in [
        {"message": "Authentication success", "username": "guest", "password": ""},
        {"message": "User input", "request_id": "r", "details": encoded("whoami")},
        {"message": "Deception response", "request_id": "r", "details": encoded("guest\n"),
         "deception_profile_id": "sample", "response_origin": "deterministic", "behavior": "identity"},
        {"message": "Session summary", "judgement": "UNKNOWN", "details": "Activity"}]]
    observations = [{"protocol": "ssh", "action": {"operation": "exec", "parameters": {}},
                     "facts": {"outputs": [{"command": "whoami", "body_base64": encoded("guest\n")}]}}]
    return records, observations


@pytest.mark.parametrize("mutation", ["origin", "profile", "auth", "input", "orphan"])
def test_telemetry_checks_metadata_auth_and_captured_input(mutation):
    records, observations = fixture()
    assert audit(records, observations, {"sample"})["status"] == "passed"
    changed = deepcopy(records)
    if mutation == "origin":
        changed[2]["response_origin"] = "llm"
    elif mutation == "profile":
        changed[2].pop("profile_id")
    elif mutation == "auth":
        changed[0].pop("password")
    elif mutation == "input":
        changed[1]["details"] = encoded("unrelated command")
    else:
        changed.append(changed[2] | {"request_id": "orphan"})
    assert audit(changed, observations, {"sample"})["status"] == "failed"
