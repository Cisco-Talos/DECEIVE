from __future__ import annotations

import asyncio
import base64
from contextlib import AsyncExitStack
from datetime import datetime, timezone
import io
import json
from pathlib import Path
import regex
import tempfile
from typing import Literal

import asyncssh
import httpx
from pydantic import Field, model_validator

from deceive.clients import HTTPResult, h3_connect
from deceive.config import fingerprint, load_deployment, load_profile, read_yaml
from deceive.models import Deployment, Listener, Model, Profile
from deceive.runtime import Runtime
from deceive.telemetry import Telemetry, encode


class Expected(Model):
    body: str | None = None
    body_base64: str | None = None
    contains: str | None = None
    regex: str | None = None
    status: int | None = None
    exit_status: int | None = None
    headers: list[tuple[str, str]] = Field(default_factory=list)
    json_value: object = None
    state: dict[str, str] = Field(default_factory=dict)


class Step(Model):
    command: str | None = None
    method: str = "GET"
    path: str = "/"
    body: str = ""
    body_base64: str | None = None
    headers: list[tuple[str, str]] = Field(default_factory=list)
    new_session: bool = False
    expect: Expected


class Case(Model):
    id: str
    group: Literal["required", "held_out"] = "required"
    username: str = "guest"
    password: str = ""
    overrides: dict = Field(default_factory=dict)
    steps: list[Step] = Field(min_length=1, max_length=100)
    repeat: int = Field(default=1, ge=1, le=20)
    concurrent: int = Field(default=1, ge=1, le=20)


class Suite(Model):
    schema_version: Literal[1] = 1
    id: str
    http_version: Literal["1.1", "2", "3"] = "1.1"
    held_out_min_pass_rate: float | None = Field(default=None, ge=0, le=1)
    references: list[str] = Field(default_factory=list)
    cases: list[Case] = Field(min_length=1, max_length=1000)

    @model_validator(mode="after")
    def unique_cases(self) -> Suite:
        if len({case.id for case in self.cases}) != len(self.cases):
            raise ValueError("Acceptance case IDs must be unique")
        if not any(case.group == "required" for case in self.cases):
            raise ValueError("At least one required case is needed")
        return self


def assertions(expected: Expected, result: HTTPResult, exit_status: int | None,
               state: dict) -> list[str]:
    errors = []
    if expected.body is not None and result.body != expected.body.encode():
        errors.append("body differs")
    if expected.body_base64 is not None and result.body != base64.b64decode(expected.body_base64, validate=True):
        errors.append("binary body differs")
    if expected.contains is not None and expected.contains.encode() not in result.body:
        errors.append("body missing expected content")
    if expected.regex is not None and not regex.search(expected.regex, result.body.decode("utf-8", "replace"), timeout=0.05):
        errors.append("body pattern did not match")
    if expected.status is not None and expected.status != result.status:
        errors.append(f"status {result.status}, expected {expected.status}")
    if expected.exit_status is not None and expected.exit_status != exit_status:
        errors.append("exit status differs")
    for name, value in expected.headers:
        if (name.lower().encode(), value.encode()) not in result.headers:
            errors.append(f"missing header {name}")
    if expected.json_value is not None:
        try:
            if json.loads(result.body) != expected.json_value:
                errors.append("JSON value differs")
        except ValueError:
            errors.append("body is not JSON")
    if any(state.get(key) != value for key, value in expected.state.items()):
        errors.append("session state differs")
    return errors


async def _sequence(runtime: Runtime, listener: Listener, case: Case, version: str,
                    interactive: bool) -> list[dict]:
    transcript = []
    handle = runtime.servers[listener.name]
    async with AsyncExitStack() as stack:
        connection = None
        process = None
        client = None
        for step in case.steps:
            if client is None or step.new_session:
                if client is not None:
                    await stack.aclose()
                if listener.protocol == "ssh":
                    port = handle.endpoints[0]["port"]
                    connection = await stack.enter_async_context(asyncssh.connect(
                        "127.0.0.1", port=port, username=case.username,
                        password=case.password, known_hosts=None,
                    ))
                    if interactive:
                        process = await connection.create_process(term_type="xterm")
                        await asyncio.wait_for(process.stdout.readuntil(("$ ", "# ")), 5)
                    client = connection
                elif version == "3":
                    port = next(e["port"] for e in handle.endpoints if e["transport"] == "udp")
                    client = await stack.enter_async_context(h3_connect(port))
                else:
                    port = next(e["port"] for e in handle.endpoints if e["transport"] == "tcp")
                    client = await stack.enter_async_context(httpx.AsyncClient(
                        base_url=f"{'https' if listener.protocol == 'https' else 'http'}://127.0.0.1:{port}",
                        verify=False, http1=version == "1.1", http2=version == "2",
                        follow_redirects=False, timeout=5, trust_env=False,
                    ))
            exit_status = None
            if listener.protocol == "ssh":
                if step.command is None:
                    raise ValueError("SSH steps require command")
                if interactive:
                    process.stdin.write(step.command + "\n")
                    try:
                        value = await asyncio.wait_for(process.stdout.readuntil(("$ ", "# ")), 5)
                        # Strip the final server-owned shell prompt.
                        output = value.rsplit("\n", 1)[0] + "\n" if "\n" in value else ""
                    except asyncio.IncompleteReadError as exc:
                        output = exc.partial
                        await asyncio.wait_for(process.wait_closed(), 5)
                        exit_status = process.exit_status
                        client = None
                    result = HTTPResult(200, output.encode(), [], "ssh")
                else:
                    value = await connection.run(step.command, check=False, timeout=5)
                    exit_status = value.exit_status
                    result = HTTPResult(200, value.stdout.encode(), [], "ssh")
                    # The SSH adapter deliberately permits one process per connection.
                    client = None
            else:
                body = base64.b64decode(step.body_base64, validate=True) if step.body_base64 else step.body.encode()
                headers = [(k.lower().encode(), v.encode()) for k, v in step.headers]
                if version == "3":
                    result = await client.request(step.method, step.path, body, headers)
                else:
                    response = await client.request(step.method, step.path, content=body, headers=headers)
                    actual = {"HTTP/1.1": "1.1", "HTTP/2": "2"}.get(response.http_version, response.http_version)
                    result = HTTPResult(response.status_code, response.content, list(response.headers.raw), actual)
                if result.version != version:
                    raise ValueError(f"Protocol fallback: expected HTTP/{version}, got {result.version}")
            sessions = [s for s in runtime.sessions.values() if s.listener == listener.name]
            if listener.protocol == "ssh" and connection:
                port = connection.get_extra_info("sockname")[1]
                sessions = [s for s in sessions if s.context["src_port"] == port]
            elif version != "3" and runtime.profiles[listener.name].stateful:
                token = client.cookies.get(runtime.profiles[listener.name].cookie_name)
                sessions = [s for s in sessions if s.id == token]
            state = dict(sessions[-1].state) if sessions else {}
            errors = assertions(step.expect, result, exit_status, state)
            transcript.append({"input": step.model_dump(mode="json", exclude={"expect"}),
                               "body_base64": encode(result.body), "status": result.status,
                               "headers": [[encode(k), encode(v)] for k, v in result.headers],
                               "version": result.version, "errors": errors})
    return transcript


async def evaluate(reference: str, suite_path: Path, report_dir: Path, *,
                   config_path: Path | None = None, live_model: bool = False) -> dict:
    suite_raw = read_yaml(suite_path)
    suite = Suite.model_validate(suite_raw)
    profile = load_profile(reference)
    if profile.fallback == "llm" and not live_model:
        raise ValueError("Generative evaluation requires explicit --live-model and --config")
    if live_model and config_path is None:
        raise ValueError("Live-model evaluation requires --config")
    if (report_dir / "results.json").exists():
        raise ValueError("Report already exists; choose a new report directory")
    results = []
    provider_metadata = None
    for case in suite.cases:
        case_result = {"id": case.id, "group": case.group, "passed": True, "runs": []}
        try:
            raw = profile.model_dump(mode="json")
            for key, value in case.overrides.items():
                if key not in {"identity", "behaviors", "files", "stateful", "fallback"}:
                    raise ValueError(f"Unsupported profile override: {key}")
                raw[key] = value
            candidate = Profile.model_validate(raw)
            if candidate.fallback == "llm" and not live_model:
                raise ValueError("Profile overrides cannot enable live-model evaluation")
            with tempfile.TemporaryDirectory(prefix="deceive-evaluate-") as directory:
                protocol = "ssh" if candidate.protocol == "ssh" else "http" if suite.http_version == "1.1" else "https"
                listener = Listener(name="evaluation", protocol=protocol, profile=reference,
                                    host="127.0.0.1", port=0, quic_port=0,
                                    versions=[suite.http_version], accounts={case.username: case.password})
                config = Deployment(data_dir=Path(directory), listeners=[listener])
                if live_model:
                    source = load_deployment(config_path)
                    if not source.providers:
                        raise ValueError("Evaluation configuration has no providers")
                    config.providers = source.providers
                    listener.provider = next(iter(source.providers))
                    selected = source.providers[listener.provider]
                    provider_metadata = {"kind": selected.kind, "model": selected.model,
                                         "temperature": selected.temperature}
                stream = io.StringIO()
                runtime = Runtime(config, profiles={listener.name: candidate},
                                  telemetry=Telemetry("evaluation", stream=stream))
                try:
                    await runtime.start()
                    for _ in range(case.repeat):
                        runs = await asyncio.gather(*(_sequence(runtime, listener, case, suite.http_version,
                                                   interactive=candidate.protocol == "ssh" and len(case.steps) > 1)
                                                     for _ in range(case.concurrent)))
                        case_result["runs"].extend(runs)
                    case_result["passed"] = all(not step["errors"] for run in case_result["runs"] for step in run)
                finally:
                    await runtime.close()
                case_result["telemetry"] = [json.loads(line) for line in stream.getvalue().splitlines()]
        except Exception as exc:
            # Case execution is an intentional evaluation boundary. A failed
            # connection/assertion must yield a report, not a false pass.
            case_result.update(passed=False, error=type(exc).__name__)
        results.append(case_result)
    required = [r for r in results if r["group"] == "required"]
    held_out = [r for r in results if r["group"] == "held_out"]
    rate = sum(r["passed"] for r in held_out) / len(held_out) if held_out else None
    passed = all(r["passed"] for r in required)
    if suite.held_out_min_pass_rate is not None:
        passed = passed and rate is not None and rate >= suite.held_out_min_pass_rate
    report = {"schema_version": 1, "profile_id": profile.id, "suite_id": suite.id,
              "timestamp": datetime.now(timezone.utc).isoformat(), "passed": passed,
              "profile_fingerprint": fingerprint(profile), "suite_fingerprint": fingerprint(suite_raw),
              "live_model": live_model, "provider": provider_metadata, "total_cases": len(results),
              "passed_cases": sum(r["passed"] for r in results), "held_out_pass_rate": rate,
              "cases": results}
    report_dir.mkdir(parents=True, exist_ok=True)
    (report_dir / "results.json").write_text(json.dumps(report, indent=2))
    text = f"{'PASS' if passed else 'FAIL'} {profile.id}: {report['passed_cases']}/{len(results)} cases\n"
    text += "\n".join(f"{'PASS' if r['passed'] else 'FAIL'} [{r['group']}] {r['id']}" for r in results)
    (report_dir / "summary.txt").write_text(text + "\n")
    return report
