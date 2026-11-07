from __future__ import annotations

import base64
import json


def ssh_output_matches(record: dict, output: dict, interactive: bool) -> bool:
    try:
        if (record.get('response_stage', 'final') != 'final' or
            bool(record.get("interactive")) != interactive or record.get("ssh_response_error")):
            return False
        body = base64.b64decode(record.get("ssh_stdout", record.get("details", "")), validate=True)
        stderr = base64.b64decode(record.get("ssh_stderr", ""), validate=True)
        if record.get("interactive"):
            body = (b''.join(base64.b64decode(item[1], validate=True)
                            for item in record['terminal_chunks'])
                    if record.get('terminal_chunks') else body + stderr)
        elif output.get("stderr_base64", "") != base64.b64encode(stderr).decode():
            return False
        if output.get("exit_status") is not None and "ssh_exit_status" in record:
            if output["exit_status"] != record["ssh_exit_status"]:
                return False
        return base64.b64encode(body).decode() == output["body_base64"]
    except (ValueError, TypeError, KeyError):
        return False


def audit(records: list[dict], observations: list[dict], allowed_profiles: set[str]) -> dict:
    errors = []
    inputs, responses, summaries = {}, {}, {}
    paired = []
    used_ssh_requests = set()
    terminal_offsets = {}
    terminal_input_offsets = {}
    streams, input_streams, channel_records = {}, {}, {}
    for record in records:
        if record.get('message') not in {'Terminal output', 'Terminal input'}:
            continue
        key = (record.get('task_name'), record.get('channel_id'))
        channel_records[key] = record
        inventory = streams if record['message'] == 'Terminal output' else input_streams
        inventory[key] = inventory.get(key, b'') + base64.b64decode(record['details'])

    def terminal_channels(facts: dict) -> list[tuple]:
        version = facts.get('client_version')
        return [key for key, record in channel_records.items()
                if (record.get('ssh_client_version') == version if version else
                    record.get('src_port') == facts.get('source_port'))]

    def match_terminal(channels: list[tuple], capture: bytes, sent: bytes) -> bool:
        for key in channels:
            output_offset = terminal_offsets.get(key, 0)
            input_offset = terminal_input_offsets.get(key, 0)
            if (streams.get(key, b'')[output_offset:output_offset + len(capture)] == capture
                    and input_streams.get(key, b'')[input_offset:input_offset + len(sent)] == sent):
                terminal_offsets[key] = output_offset + len(capture)
                terminal_input_offsets[key] = input_offset + len(sent)
                return True
        return False
    required = {"timestamp", "level", "task_name", "src_ip", "src_port", "dst_ip", "dst_port",
                "message", "sensor_name", "sensor_protocol"}
    for record in records:
        if required - record.keys():
            errors.append("Telemetry missing core fields")
        message = record.get("message")
        if message in {"User input", "LLM response", "Deception response"}:
            if not record.get("profile_id"):
                errors.append("Missing profile attribution")
            try:
                for key in ("details", "ssh_stdout", "ssh_stderr"):
                    if key == "details" or key in record:
                        base64.b64decode(record[key], validate=True)
            except (ValueError, TypeError, KeyError):
                errors.append("Invalid base64 content")
            if "ssh_stdout" in record and ("ssh_stderr" not in record or
                type(record.get("ssh_exit_status")) is not int or not 0 <= record["ssh_exit_status"] <= 255):
                errors.append("Invalid SSH output metadata")
            if record.get("ssh_response_error") and record.get("response_stage", "final") != "attempt":
                errors.append("Rejected SSH model reply lacks a captured wire response")
            request = record.get("request_id")
            if not request:
                errors.append("Missing request correlation")
            if message == "User input":
                if request in inputs:
                    errors.append("Duplicate input correlation")
                inputs[request] = record
            else:
                if record.get('response_stage', 'final') == 'final':
                    responses.setdefault(request, []).append(record)
                elif record.get('response_stage') == 'component' and record.get('component_command'):
                    pass
                elif record.get('response_stage') != 'attempt' or record.get('attempt') not in (1, 2):
                    errors.append('Invalid model attempt metadata')
                expected_origin = "llm" if message == "LLM response" else "deterministic"
                if record.get("response_origin") != expected_origin:
                    errors.append("Response origin does not match message type")
                owner = record.get("deception_profile_id")
                if owner and owner not in allowed_profiles:
                    errors.append("Response attributed to an unexpected profile")
        if message == "Session summary":
            session = record.get("task_name")
            summaries[session] = summaries.get(session, 0) + 1
            if record.get("judgement") not in {"BENIGN", "SUSPICIOUS", "MALICIOUS", "UNKNOWN"}:
                errors.append("Invalid summary judgement")
        if message == "User attempting to authenticate" and "username" not in record:
            errors.append("Authentication attempt lacks username")
        if message in {"Authentication success", "Authentication failed"} and (
            "username" not in record or "password" not in record
        ):
            errors.append("Authentication result lacks attempted credentials")
    for request, record in inputs.items():
        if len(responses.get(request, [])) != 1:
            errors.append("Input does not have exactly one response")
        elif responses[request][0].get("task_name") != record.get("task_name"):
            errors.append("Input/response session mismatch")
        else:
            paired.append((record, responses[request][0]))
        if summaries.get(record.get("task_name")) != 1:
            errors.append("Observed session does not have exactly one summary")
    if any(count > 1 for count in summaries.values()):
        errors.append("Duplicate session summary")
    if responses.keys() - inputs.keys():
        errors.append("Response lacks correlated input")
    for observation in observations:
        if observation.get("error") or observation["action"]["operation"] in {
            "close", "h2_method", "h2_resets", "h3_fin"
        }:
            continue
        if observation["protocol"] == "ssh":
            if observation['action']['operation'] == 'terminal':
                facts = observation.get('facts', {})
                capture = b''.join(base64.b64decode(item.get('raw_base64', ''))
                    for item in facts.get('terminal', []))
                sent = ''.join(event.get('send', '') for event in
                               observation['action']['parameters'].get('events', [])).encode()
                if not match_terminal(terminal_channels(facts), capture, sent):
                    errors.append('Client terminal capture not found in ordered telemetry')
                continue
            outputs = observation.get("facts", {}).get("outputs", [])
            action = observation["action"]
            parameters = action.get("parameters", {})
            interactive = bool(action.get("session") or parameters.get("interactive") or
                               len(parameters.get("commands", [])) > 1)
            channels = terminal_channels(observation.get('facts', {}))
            if interactive and channels:
                capture = b''.join(base64.b64decode(output['raw_base64']) for output in outputs)
                # The named command client consumes the login banner once; later
                # observations report it as metadata without reading it again.
                if all(key not in terminal_offsets for key in channels):
                    capture = base64.b64decode(observation['facts'].get('banner_base64', '')) + capture
                sent = ''.join(output['command'] + '\n' for output in outputs).encode()
                if not match_terminal(channels, capture, sent):
                    errors.append('Client SSH input/output pair not found in ordered terminal telemetry')
                continue
            for output in outputs:
                command = base64.b64encode(output["command"].encode()).decode()
                match = next((before["request_id"] for before, after in paired
                    if before["request_id"] not in used_ssh_requests
                    and before.get("details") == command
                    and ssh_output_matches(after, output, interactive)), None)
                if match is None:
                    errors.append("Client SSH input/output pair not found in telemetry")
                else:
                    used_ssh_requests.add(match)
        elif observation["protocol"] in {"http", "https"}:
            parameters = observation["action"]["parameters"]
            method = parameters.get("method", "GET").upper()
            body = parameters.get("body_base64", base64.b64encode(parameters.get("body", "").encode()).decode())
            suppressed = method == "HEAD" or observation.get("facts", {}).get("status") in {204, 304}
            matches = []
            for before, after in paired:
                try:
                    captured = json.loads(base64.b64decode(before.get("details", "")))
                except (ValueError, UnicodeError):
                    continue
                if not isinstance(captured, dict):
                    continue
                matches.append(captured.get("method") == method and captured.get("body") == body
                    and after.get("http_status", observation.get("facts", {}).get("status")) == observation.get("facts", {}).get("status")
                    and (suppressed or after.get('response_body_base64', after.get("details")) == observation.get("body_base64")))
            if not any(matches):
                errors.append("Client HTTP input/output pair not found in telemetry")
    return {"status": "passed" if not errors else "failed", "errors": sorted(set(errors)),
            "inputs": len(inputs), "summaries": sum(summaries.values()),
            "observations": len(observations)}


def parse_logs(text: str, sensor: str) -> list[dict]:
    records = []
    for line in text.splitlines():
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if isinstance(value, dict) and value.get("sensor_name") == sensor:
            records.append(value)
    return records
