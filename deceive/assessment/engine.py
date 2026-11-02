from __future__ import annotations

import asyncio
import base64
from importlib.resources import files
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import hashlib

from deceive.assessment.broker import rpc
from deceive.assessment.docker import Docker, deploy
from deceive.assessment.models import CandidateManifest, Decisions, LoopResult, ProbeAction, Review, Spec
from deceive.assessment.scoring import exit_reason, quality_confirmed, target_score
from deceive.assessment.telemetry import audit, parse_logs
from deceive.assessment.workspace import checkpoint, git, load_json, locked, now, source_files, target_deployment, write_json
from deceive.composition import resolve
from deceive.config import fingerprint, read_yaml
from deceive.evaluate import evaluate_external
from deceive.vulnerability_catalog import approval_for


def source_identity(root: Path) -> str:
    import hashlib
    return fingerprint({str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
                        for p in source_files(root)})


def check_fresh(state: dict) -> None:
    root = Path(state["root"])
    if git(root, "branch", "--show-current").strip() != state["baseline"]["branch"]:
        raise ValueError("Assessment branch changed; preserve edits and resume on the recorded branch")
    if state.get("current") and source_identity(root) != state["current"]["source"]["source_id"]:
        raise ValueError("Candidate changed during assessment; begin-loop --retry to reassess the new revision")
    if state.get("current") and definitions_identity(Spec.model_validate(state["spec"])) != state["current"].get("definitions_id"):
        raise ValueError("Profile/config/assets changed during assessment; begin-loop --retry")


def definitions_identity(spec: Spec) -> str:
    definitions = {}
    known = {}
    for target in spec.targets:
        config = target_deployment(spec, target)
        plan = resolve(config)
        definitions[target.name] = {"config": config.model_dump(mode="json"),
            "profiles": {name: fingerprint(profile) for name, profile in plan.profiles.items()},
            "suite": fingerprint(read_yaml(Path(target.suite))) if target.suite else None}
        for members in plan.members.values():
            for profile in members:
                identity = fingerprint(profile)
                if profile.id in known and known[profile.id] != identity:
                    raise ValueError(f"Conflicting catalog definitions for {profile.id}")
                known[profile.id] = identity
    return fingerprint(definitions)


def claim_repository(run: Path, state: dict) -> None:
    owner = Path(state["root"]) / ".deceive" / "assessment-owner.json"
    if owner.exists():
        previous = load_json(owner)
        if previous["run"] != str(run):
            previous_state = Path(previous["run"]) / "state.json"
            if previous_state.exists() and load_json(previous_state)["phase"] != "finished":
                raise ValueError("Another assessment owns repairs in this repository; finish/cleanup that run first")
    write_json(owner, {"run": str(run), "run_id": state["run_id"]})


async def stop_broker(run: Path) -> None:
    state = load_json(run / "state.json")
    if (state.get("current") or {}).get("broker"):
        try:
            await rpc(run, {"operation": "shutdown"})
        except (OSError, ValueError, TimeoutError):
            pass
        socket = Path(state["current"]["broker"]["socket"])
        for _ in range(40):
            if not socket.exists():
                break
            await asyncio.sleep(0.05)


async def start_broker(run: Path, state: dict) -> None:
    directory = run / state["current"]["directory"]
    sock = Path(tempfile.gettempdir()) / (state["run_id"] + ".sock")
    state["current"]["broker"] = {"socket": str(sock), "token": secrets.token_hex(32)}
    write_json(run / "state.json", state)
    with (directory / "broker.log").open("a") as log:
        process = subprocess.Popen([sys.executable, "-m", "deceive.assessment.broker", "--run", str(run)],
                                   stdout=log, stderr=log, start_new_session=True)
    state["current"]["broker"]["pid"] = process.pid
    write_json(run / "state.json", state)
    for _ in range(100):
        try:
            await rpc(run, {"operation": "ping"})
            return
        except (OSError, ValueError):
            if process.poll() is not None:
                raise RuntimeError("Probe broker exited; inspect its private broker.log")
            await asyncio.sleep(0.05)
    raise RuntimeError("Probe broker did not become ready")


def public_state(state: dict) -> dict:
    current = state.get("current")
    targets = {}
    if current:
        for handle, entry in current["targets"].items():
            targets[handle] = {"available": not bool(entry.get("error")),
                "claims": entry.get("claims", ""), "references": entry.get("references", []),
                "limitations": entry.get("limitations", []), "services": [
                    {k: e[k] for k in ("id", "protocol", "versions")}
                    for e in entry.get("endpoints", [])]}
    return {"run_id": state["run_id"], "phase": state["phase"],
            "candidate_id": current["candidate_id"] if current else None,
            "loop": current["number"] if current else len(state["loops"]),
            "targets": targets, "limits": state["spec"]["limits"],
            "stop_reason": state.get("stop_reason"),
            "session_reset_on_resume": bool(current and current.get("session_reset_on_resume")),
            "action_examples": {
                "ssh": {"operation": "exec", "endpoint": "service-1", "session": "visit",
                        "parameters": {"command": "hostname"}},
                "http": {"operation": "request", "endpoint": "service-1", "session": "visit",
                         "parameters": {"version": "1.1", "method": "GET", "path": "/"}},
                "close": {"operation": "close", "endpoint": "service-1", "session": "visit"}}}


async def begin_loop(run: Path, *, retry: bool = False, docker: Docker | None = None) -> dict:
    docker = docker or Docker()
    with locked(run):
        state = load_json(run / "state.json")
        spec = Spec.model_validate(state["spec"])
        claim_repository(run, state)
        if state["phase"] == "finished" or (state.get("stop_reason") and not retry):
            raise ValueError("Run reached its exit condition; finish it or prepare a new run")
        if state["phase"] == "active" and not retry:
            raise ValueError("Loop already active; resume it or use --retry after repairs")
        if retry:
            await stop_broker(run)
        docker.preflight()
        number = len(state["loops"]) + 1
        if number > spec.policy.max_loops:
            raise ValueError("Loop count limit reached")
        if spec.limits.max_elapsed_seconds and time.time() - state["started_epoch"] >= spec.limits.max_elapsed_seconds:
            state["stop_reason"] = "budget_exhausted"
            write_json(run / "state.json", state)
            raise ValueError("Run elapsed-time budget exhausted; finish to render partial results")
        attempt = state["current"]["attempt"] + 1 if retry and state.get("current") else 1
        directory = Path(f"loop-{number:04d}") / f"attempt-{attempt:02d}"
        loop_dir = run / directory
        loop_dir.mkdir(parents=True)
        source = checkpoint(Path(state["root"]), loop_dir)
        # Profile/config fingerprints are added after complete dependency staging.
        current = {"schema_version": 1, "number": number, "attempt": attempt, "directory": str(directory),
                   "started": now(), "source": source, "candidate_id": "pending",
                   "targets": {}, "correctness": {}, "reviews": {},
                   "definitions_id": definitions_identity(spec)}
        state.update(current=current, phase="active", stop_reason=None)
        write_json(run / "state.json", state)
        try:
            image = await asyncio.to_thread(docker.image, spec, source, loop_dir)
            current["image"] = image
            definitions = {}
            for index, target in enumerate(spec.targets):
                handle = f"target-{index + 1:02d}"
                try:
                    for allocation_attempt in range(3):
                        try:
                            entry = await deploy(docker, run, state, spec, target, handle, image, loop_dir)
                            break
                        except RuntimeError as exc:
                            if allocation_attempt == 2 or not any(s in str(exc).lower() for s in (
                                "port is already allocated", "address already in use", "ports are not available")):
                                raise
                            stale = state["containers"].get(handle)
                            if stale:
                                archive = loop_dir / "targets" / handle
                                archive.mkdir(parents=True, exist_ok=True)
                                (archive / f"allocation-{allocation_attempt}.log").write_text(
                                    docker.call("logs", stale["container"]))
                                docker.remove(stale, state["run_id"])
                                state["containers"].pop(handle)
                                write_json(run / "state.json", state)
                    entry["claims"] = target.claims or " ".join(p["description"] for p in entry["profiles"])
                    entry["references"] = sorted({r for p in entry["profiles"] for r in p["references"]})
                    entry["limitations"] = sorted({r for p in entry["profiles"] for r in p["limitations"]})
                    current["targets"][handle] = entry
                    stage = Path(entry["stage"])
                    normalized = {}
                    for p in stage.iterdir():
                        if not p.is_file():
                            continue
                        data = p.read_bytes()
                        if p.name == "deployment.yaml":
                            value = json.loads(data)
                            value.pop("sensor_name", None)
                            for listener in value["listeners"]:
                                listener["advertised_port"] = None
                            data = json.dumps(value, sort_keys=True).encode()
                        normalized[p.name] = hashlib.sha256(data).hexdigest()
                    definitions[handle] = normalized
                except (OSError, ValueError, RuntimeError) as exc:
                    current["targets"][handle] = {"error": str(exc), "target_name": target.name,
                                                  "calibration": bool(target.calibration)}
                    current["correctness"][handle] = {"status": "failed", "error": str(exc)}
            assessment_context = {k: v for k, v in state["spec"].items()
                                  if k not in {"policy", "limits", "docker"}}
            current["candidate_id"] = fingerprint({"source": source["source_id"],
                "definitions": definitions, "definitions_id": current["definitions_id"],
                "spec": assessment_context})
            # Compare definitions without per-loop sensor names or transient ports.
            current["comparison_id"] = fingerprint(assessment_context | {
                "review_revision": source.get("review_id"), "policy": {
                    k: v for k, v in state["spec"]["policy"].items()
                    if k not in {"mode", "max_loops"}}})
            CandidateManifest.model_validate(current)
            write_json(run / "state.json", state)
            await start_broker(run, state)
            for handle, entry in current["targets"].items():
                if entry.get("error"):
                    continue
                current["correctness"][handle] = await acceptance(run, state, spec, handle, docker)
                write_json(run / "state.json", state)
            write_json(loop_dir / "candidate.json", current)
            write_json(loop_dir / "review-briefing.json", public_state(state))
            return public_state(state)
        except BaseException:
            await stop_broker(run)
            for entry in state["containers"].values():
                try:
                    docker.stop(entry, state["run_id"])
                except (ValueError, RuntimeError):
                    pass
            state["phase"] = "interrupted"
            write_json(run / "state.json", state)
            from deceive.assessment.dashboard import render
            render(run)
            raise


async def acceptance(run: Path, state: dict, spec: Spec, handle: str, docker: Docker) -> dict:
    current, reports = state["current"], []
    entry = current["targets"][handle]
    target = next(t for t in spec.targets if t.name == entry["target_name"])
    directory = run / current["directory"] / "targets" / handle
    for profile in entry["profiles"]:
        endpoint = next(e for e in entry["endpoints"] if e["listener"] == profile["listener"])
        suite = Path(target.suite) if target.suite else Path(str(files("deceive").joinpath(
            "acceptance", profile["id"] + ".yaml")))
        if not suite.is_file():
            reports.append({"profile_id": profile["id"], "passed": False, "error": "No acceptance suite"})
            continue
        raw = read_yaml(suite)
        try:
            criteria_key = entry["target_name"] + "/" + profile["id"]
            accepted = state.setdefault("criteria", {}).setdefault(criteria_key, fingerprint(raw))
            if accepted != fingerprint(raw):
                raise ValueError("Frozen run acceptance criteria changed; prepare a separately agreed run")
            if profile["id"] in __import__("deceive.vulnerability_catalog", fromlist=["bundled_vulnerabilities"]).bundled_vulnerabilities():
                if fingerprint(raw) != approval_for(profile["id"])["suites"][profile["id"]]:
                    raise ValueError("Frozen acceptance criteria changed")
            variants = []
            for version in endpoint["versions"] if endpoint["protocol"] != "ssh" else ["ssh"]:
                async def execute(action):
                    return await rpc(run, {"role": "acceptance", "target": handle,
                        "action": action | {"endpoint": endpoint["id"]}})
                variants.append(await evaluate_external(suite, endpoint["protocol"], version, execute))
            # Protected variants run in fresh loopback listeners inside the same
            # candidate image using the staged profile, not the bundled old copy.
            stage = Path(entry["stage"])
            name = "suite-" + profile["id"] + ".json"
            (stage / name).write_text(json.dumps(raw))
            (stage / name).chmod(0o644)
            config = json.loads((stage / "deployment.yaml").read_text())
            listener = next(l for l in config["listeners"] if l["name"] == profile["listener"])
            reference = profile.get("staged_reference") or listener["profile"] or listener["profiles"][0]
            program = """import asyncio,importlib.util,json,sys,tempfile
from pathlib import Path
for name in ('clients','evaluate'):
    loader=importlib.util.spec_from_file_location('deceive.'+name, '/stage/current_'+name+'.py')
    module=importlib.util.module_from_spec(loader);sys.modules['deceive.'+name]=module;loader.loader.exec_module(module)
from deceive.evaluate import evaluate
with tempfile.TemporaryDirectory() as directory:
    result=asyncio.run(evaluate(sys.argv[1],Path(sys.argv[2]),Path(directory)/'report',
        config_path=Path('/stage/deployment.yaml') if sys.argv[3]=='1' else None,live_model=sys.argv[3]=='1'))
    print(json.dumps(result))
"""
            full = json.loads(await asyncio.to_thread(docker.call, "exec", entry["container"],
                "python", "-c", program, reference, "/stage/" + name,
                "1" if listener.get("provider") else "0", timeout=300))
            passed = full["passed"] and all(v["external_passed"] for v in variants)
            report = {"profile_id": profile["id"], "passed": passed,
                      "external": variants, "docker_loopback_with_variants": full}
            write_json(directory / (profile["id"] + "-acceptance.json"), report)
            reports.append({"profile_id": profile["id"], "passed": bool(passed)})
        except (OSError, ValueError, RuntimeError) as exc:
            reports.append({"profile_id": profile["id"], "passed": False, "error": str(exc)[:500]})
    return {"status": "passed" if reports and all(r["passed"] for r in reports) else "failed",
            "profiles": reports}


def record_review(run: Path, report: Review) -> dict:
    with locked(run):
        state = load_json(run / "state.json")
        check_fresh(state)
        current = state["current"]
        if state["phase"] != "active" or report.candidate_id != current["candidate_id"]:
            raise ValueError("Review does not match the active candidate")
        if report.role not in state["spec"]["roles"] or report.target not in current["targets"]:
            raise ValueError("Review role/target is not in the selected scope")
        directory = run / current["directory"]
        observations = read_observations(directory)
        evidence = {o["interaction_id"] for o in observations if o["role"] == report.role
                    and o["target"] == report.target and o["action"]["operation"] != "close"}
        if not evidence:
            raise ValueError("A review needs active interaction evidence for this role/target")
        for finding in report.findings:
            if not set(finding.evidence).issubset(evidence):
                raise ValueError("Finding references unknown or another reviewer's evidence")
        key = report.role + "/" + report.target
        path = directory / "reviews" / (report.role + "-" + report.target + ".json")
        if path.exists():
            previous = path.with_name(path.stem + "-previous-" + str(time.time_ns()) + ".json")
            shutil.copy2(path, previous)
        write_json(path, report.model_dump(mode="json"))
        current["reviews"][key] = str(path.relative_to(run))
        write_json(run / "state.json", state)
        return {"recorded": key, "active_interactions": len(evidence)}


def read_observations(directory: Path) -> list[dict]:
    path = directory / "observations.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


async def end_loop(run: Path, decisions: Decisions | None = None, *, plateau_confirmed: bool = False,
                   docker: Docker | None = None) -> dict:
    docker = docker or Docker()
    decisions = decisions or Decisions()
    with locked(run):
        state = load_json(run / "state.json")
        if state["phase"] != "active":
            raise ValueError("No active loop")
        check_fresh(state)
        current = state["current"]
        directory = run / current["directory"]
        await stop_broker(run)
        observations = read_observations(directory)
        roles = state["spec"]["roles"]
        spec = Spec.model_validate(state["spec"])
        targets, findings = {}, []
        previous = {f["key"]: f | {"candidate_id": f.get("candidate_id", loop["candidate_id"])}
                    for loop in state["loops"] for f in loop["findings"]
                    if not loop["targets"][f["target"]].get("calibration")}
        calibration_passed = True
        for handle, entry in current["targets"].items():
            records = []
            telemetry = {"status": "unassessed", "errors": ["Target unavailable"]}
            if not entry.get("error"):
                try:
                    docker.stop(entry, state["run_id"])
                    logs = docker.call("logs", entry["container"])
                    records = parse_logs(logs, entry["sensor"])
                    write_json(directory / "targets" / handle / "telemetry.json", records)
                    allowed = set(entry.get("allowed_profile_ids", [p["id"] for p in entry["profiles"]]))
                    telemetry = audit(records, [o for o in observations if o["target"] == handle], allowed)
                except (OSError, RuntimeError, ValueError) as exc:
                    telemetry = {"status": "failed", "errors": [str(exc)]}
            reviews = [load_json(run / path) for key, path in current["reviews"].items()
                       if key.split("/")[1] == handle]
            score = target_score(reviews, roles)
            services = [e["id"] for e in entry.get("endpoints", [])]
            coverage = {role: {service: any(o["role"] == role and o["target"] == handle
                and not o.get("error") and o["action"]["operation"] != "close"
                and (o["action"].get("endpoint") == service or
                     (len(services) == 1 and not o["action"].get("endpoint")))
                for o in observations) for service in services} for role in roles}
            score["complete"] = score["complete"] and bool(services) and all(
                all(seen.values()) for seen in coverage.values())
            critical = False
            for review in reviews:
                for finding in review["findings"]:
                    key = review["role"] + "/" + handle + "/" + finding["id"]
                    decision = decisions.findings.get(key)
                    prior = previous.get(key)
                    verification = (decision.model_dump() if decision else
                        prior["verification"] if prior and prior["verification"]["status"] == "verified"
                        else {"status": "unproven"})
                    status = verification["status"]
                    if finding["severity"] in {"P0", "P1"} and status not in {"false_positive", "resolved"}:
                        critical = True
                    if prior and not decision and prior["severity"] < finding["severity"]:
                        findings.append(prior | {"latest_evidence": finding["evidence"]})
                        critical |= prior["severity"] in {"P0", "P1"}
                        continue
                    findings.append(finding | {"key": key, "candidate_id": current["candidate_id"],
                        "reviewer": review["role"], "target": handle,
                        "profile_ids": [p["id"] for p in entry.get("profiles", [])],
                        "verification": verification})
            current_keys = {f["key"] for f in findings}
            for key, prior in previous.items():
                if prior["target"] != handle or key in current_keys or prior["verification"]["status"] in {"resolved", "false_positive"}:
                    continue
                decision = decisions.findings.get(key)
                carried = prior | {"carried_forward": True, "verification":
                    decision.model_dump() if decision else prior["verification"]}
                findings.append(carried)
                if carried["severity"] in {"P0", "P1"} and carried["verification"]["status"] not in {"resolved", "false_positive"}:
                    critical = True
            correctness = current["correctness"].get(handle, {"status": "unassessed"})
            disagreement = score["spread"] is not None and score["spread"] > spec.policy.disagreement
            qualified = (score["complete"] and score["median"] >= spec.policy.minimum_realism
                and correctness["status"] == telemetry["status"] == "passed" and not critical
                and (not disagreement or bool(decisions.reconciliations.get(handle))))
            target_result = score | {"qualified": bool(qualified), "correctness": correctness,
                "telemetry": telemetry, "profiles": entry.get("profiles", []),
                "calibration": entry.get("calibration", False), "disagreement": disagreement,
                "coverage": coverage}
            if entry.get("calibration"):
                # Calibration must be observed, not counted as a failed production deception.
                detected = any(f["target"] == handle and f["verification"]["status"] == "verified"
                               and f["category"] in {"response_format", "vulnerability_semantics",
                                                      "identity_or_state", "operational_tell"}
                               for f in findings)
                target_result["calibration_detected"] = detected
                calibration_passed &= detected and score["complete"]
            targets[handle] = target_result
        actual = {k: v for k, v in targets.items() if not v["calibration"]}
        complete = bool(actual) and all(v["complete"] for v in targets.values())
        result = {"schema_version": 1, "loop": current["number"], "attempt": current["attempt"],
            "candidate_id": current["candidate_id"], "comparison_id": current["comparison_id"],
            "source": current["source"], "image": current.get("image"), "client_id": current["source"]["client_id"],
            "complete": complete, "qualified": bool(actual) and calibration_passed
                and all(v["qualified"] for v in actual.values()),
            "targets": targets, "findings": findings, "progress": decisions.progress,
            "plateau_confirmed": plateau_confirmed, "calibration_passed": calibration_passed,
            "started": current["started"], "finished": now(), "native_agent_usage": None,
            "directory": current["directory"]}
        state["loops"].append(result)
        LoopResult.model_validate(result)
        state["phase"] = "between_loops"
        state["stop_reason"] = exit_reason(state["loops"], spec.policy)
        write_json(directory / "scores.json", result)
        write_json(directory / "decisions.json", decisions.model_dump(mode="json"))
        write_json(run / "state.json", state)
        from deceive.assessment.dashboard import render
        render(run)
        return {"loop": result["loop"], "complete": complete, "qualified": result["qualified"],
                "stop_reason": state["stop_reason"], "targets": {k: {"median": v["median"],
                    "qualified": v["qualified"], "correctness": v["correctness"]["status"],
                    "telemetry": v["telemetry"]["status"]} for k, v in targets.items()}}


async def finish(run: Path, *, remove: bool = False, reason: str | None = None,
                 docker: Docker | None = None) -> dict:
    docker = docker or Docker()
    with locked(run):
        state = load_json(run / "state.json")
        remove = remove or not state["spec"]["docker"]["retain"]
        fresh = True
        try:
            check_fresh(state)
        except ValueError:
            fresh = False
        await stop_broker(run)
        errors = []
        for handle, entry in state["containers"].items():
            try:
                docker.stop(entry, state["run_id"])
                if state.get("current"):
                    directory = run / state["current"]["directory"] / "targets" / handle
                    write_json(directory / "final-telemetry.json", parse_logs(
                        docker.call("logs", entry["container"]), entry["sensor"]))
                if remove:
                    docker.remove(entry, state["run_id"], volumes=True)
            except (ValueError, RuntimeError) as exc:
                errors.append(str(exc))
        if remove and state.get("network"):
            try:
                docker.remove_network(state["network"], state["run_id"])
                state.pop("network", None)
            except (RuntimeError, ValueError) as exc:
                errors.append(str(exc))
        if remove and not errors:
            state["containers"] = {}
        state["phase"] = "finished"
        state["stop_reason"] = state.get("stop_reason") or reason or "incomplete"
        state["teardown_errors"] = errors
        state["final_candidate_fresh"] = fresh
        write_json(run / "state.json", state)
        from deceive.assessment.dashboard import render
        path = render(run)
        qualified = fresh and quality_confirmed(state["loops"], Spec.model_validate(state["spec"]).policy)
        if state.get("current") and state["current"]["number"] > len(state["loops"]):
            qualified = False
        return {"status": state["stop_reason"], "qualified": bool(qualified),
                "candidate_fresh": fresh, "dashboard": str(path), "teardown_errors": errors}


async def resume(run: Path, *, additional_loops: int = 0) -> dict:
    with locked(run):
        state = load_json(run / "state.json")
        claim_repository(run, state)
        if additional_loops:
            if additional_loops < 1 or additional_loops > 10000:
                raise ValueError("additional_loops must be between 1 and 10000")
            if state["phase"] == "active":
                raise ValueError("Finish the active loop before extending the run")
            state.setdefault("policy_history", []).append({"timestamp": now(), "policy": state["spec"]["policy"]})
            policy = dict(state["spec"]["policy"], max_loops=len(state["loops"]) + additional_loops)
            state["spec"]["policy"] = policy
            Spec.model_validate(state["spec"])
            state.update(phase="between_loops", stop_reason=None)
            write_json(run / "state.json", state)
        if state["phase"] == "active":
            check_fresh(state)
            try:
                await rpc(run, {"operation": "ping"})
            except (OSError, ValueError):
                state["current"]["session_reset_on_resume"] = True
                await start_broker(run, state)
        return public_state(state)
