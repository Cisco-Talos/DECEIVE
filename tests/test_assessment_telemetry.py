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


@pytest.mark.parametrize("interactive", [False, True])
def test_structured_ssh_logs_preserve_model_text_and_match_wire_streams(interactive):
    records, observations = fixture()
    if interactive:
        observations[0]["action"]["session"] = "terminal"
    records[2].update(message="LLM response", response_origin="llm", details=encoded('{"exit_status":7}'),
                      interactive=interactive, ssh_stdout=encoded("out"), ssh_stderr=encoded("error\n"), ssh_exit_status=7)
    output = observations[0]["facts"]["outputs"][0]
    output.update(body_base64=encoded("outerror\n" if interactive else "out"),
                  stderr_base64=encoded("" if interactive else "error\n"), exit_status=None if interactive else 7)
    assert audit(records, observations, {"sample"})["status"] == "passed"
    output["body_base64"] = encoded("wrong")
    assert audit(records, observations, {"sample"})["status"] == "failed"


def test_exec_failure_cannot_borrow_an_interactive_response():
    records, observations = fixture()
    records[1]['details'] = encoded('false')
    records[2].update(interactive=True, details='', ssh_stdout='', ssh_stderr='', ssh_exit_status=1)
    observations[0]['facts']['outputs'][0].update(command='false', body_base64='',
        stderr_base64=encoded('Session unavailable.\n'), exit_status=1)
    assert audit(records, observations, {'sample'})['status'] == 'failed'


def test_one_captured_request_cannot_cover_two_independent_observations():
    records, observations = fixture()
    observations.append(deepcopy(observations[0]))
    assert audit(records, observations, {'sample'})['status'] == 'failed'


def test_rejected_model_reply_is_not_a_captured_wire_response():
    records, observations = fixture()
    records[2].update(message='LLM response', response_origin='llm',
        ssh_response_error='invalid_format')
    assert audit(records, observations, {'sample'})['status'] == 'failed'
