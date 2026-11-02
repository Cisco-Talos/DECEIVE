import json
import base64
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET

import pytest

from deceive.assessment import engine
from deceive.assessment.dashboard import render
from deceive.assessment.models import Decisions, Review
from deceive.assessment.workspace import checkpoint, load_json, prepare, stage_profile, write_json


class FakeDocker:
    def __init__(self):
        self.entries = {}
        self.stopped = []

    def preflight(self):
        pass

    def image(self, *args):
        return "sha256:test-image"

    def stop(self, entry, owner):
        self.stopped.append(entry["container"])

    def call(self, operation, *args, **kwargs):
        if operation != "logs":
            return ""
        entry = self.entries[args[0]]
        common = {"timestamp": "2026-11-02T00:00:00.000+00:00", "level": "INFO",
                  "task_name": "session-one", "src_ip": "127.0.0.1", "src_port": 1,
                  "dst_ip": "127.0.0.1", "dst_port": 2, "sensor_protocol": "http",
                  "sensor_name": entry["sensor"]}
        common["profile_id"] = "demo-http"
        return "\n".join(json.dumps(common | r) for r in [
            {"message": "User input", "request_id": "r", "details": base64.b64encode(
                json.dumps({"method": "GET", "body": ""}).encode()).decode()},
            {"message": "Deception response", "request_id": "r", "details": "", "response_origin": "deterministic"},
            {"message": "Session summary", "judgement": "UNKNOWN", "details": "Activity"}])


@pytest.fixture
def assessment(tmp_path, monkeypatch):
    root = tmp_path / "repo"
    root.mkdir()
    (root / "deceive").mkdir()
    marker = root / "deceive/marker.py"
    marker.write_text("original = True\n")
    for command in (["git", "init", "-q", str(root)], ["git", "-C", str(root), "add", "."],
                    ["git", "-C", str(root), "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                     "commit", "-qm", "fixture"]):
        subprocess.run(command, check=True, capture_output=True)
    marker.write_text("original = True\nuser_edit = 'preserve me'\n")
    spec = tmp_path / "spec.yaml"
    spec.write_text('targets: [{name: web, profiles: [demo-http]}]\npolicy: {mode: fixed, max_loops: 20}\n')
    run = tmp_path / "results"
    prepare(spec, run, root)
    docker = FakeDocker()

    async def deploy(docker, run, state, spec, target, handle, image, loop_dir):
        stage = run / "stage"
        stage.mkdir(exist_ok=True)
        (stage / "deployment.yaml").write_text(json.dumps({"sensor_name": str(state["current"]["number"]),
                                                         "listeners": []}))
        entry = {"container": handle, "volume": handle, "layout": "layout", "image": image,
                 "endpoints": [{"id": "service-1", "protocol": "http", "versions": ["1.1"]}],
                 "profiles": [{"id": "demo-http", "version": "1", "fingerprint": "p",
                               "description": "Application", "references": [], "limitations": []}],
                 "calibration": False, "target_name": target.name, "stage": str(stage),
                 "sensor": "loop-" + str(state["current"]["number"])}
        state["containers"][handle] = entry
        docker.entries[handle] = entry
        return entry

    async def acceptance(*args):
        return {"status": "passed"}

    async def broker(*args):
        pass

    monkeypatch.setattr(engine, "deploy", deploy)
    monkeypatch.setattr(engine, "acceptance", acceptance)
    monkeypatch.setattr(engine, "start_broker", broker)
    monkeypatch.setattr(engine, "stop_broker", broker)
    return run, root, docker


def add_reviews(run, score=90):
    state = load_json(run / "state.json")
    current = state["current"]
    directory = run / current["directory"]
    for role in state["spec"]["roles"]:
        with (directory / "observations.jsonl").open("a") as stream:
            stream.write(json.dumps({"interaction_id": role, "target": "target-01", "role": role,
                "candidate_id": current["candidate_id"], "protocol": "http", "body_base64": "",
                "action": {"operation": "request", "endpoint": "service-1", "parameters": {}}, "facts": {"status": 200}}) + "\n")
        engine.record_review(run, Review(candidate_id=current["candidate_id"], role=role,
            target="target-01", synthetic_confidence=100-score, verdict_confidence=70,
            summary="Active mock review"))


@pytest.mark.asyncio
async def test_twenty_loops_preserve_working_tree_and_do_not_commit(assessment):
    run, root, docker = assessment
    head = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"])
    identity = None
    for number in range(1, 21):
        public = await engine.begin_loop(run, docker=docker)
        identity = identity or public["candidate_id"]
        assert public["candidate_id"] == identity
        add_reviews(run)
        result = await engine.end_loop(run, docker=docker)
        assert result["qualified"], result
        assert result["stop_reason"] == ("count_complete" if number == 20 else None)
    assert subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"]) == head
    assert "preserve me" in (root / "deceive/marker.py").read_text()
    assert len(load_json(run / "state.json")["loops"]) == 20
    final = await engine.finish(run, docker=docker)
    assert final["qualified"] and final["status"] == "count_complete"
    ET.parse(run / "dashboard.svg")
    assert "rolling5" in (run / "dashboard.svg").read_text()


@pytest.mark.asyncio
async def test_failed_gate_repairs_and_candidate_freshness(assessment, monkeypatch):
    run, root, docker = assessment
    state = load_json(run / "state.json")
    state["spec"]["policy"]["mode"] = "until"
    write_json(run / "state.json", state)
    await engine.begin_loop(run, docker=docker)
    state = load_json(run / "state.json")
    state["current"]["correctness"]["target-01"] = {"status": "failed", "error": "missing behavior"}
    write_json(run / "state.json", state)
    add_reviews(run)
    first = await engine.end_loop(run, docker=docker)
    assert not first["qualified"] and first["stop_reason"] is None
    with (root / "deceive/marker.py").open("a") as stream:
        stream.write("repair = True\n")
    await engine.begin_loop(run, docker=docker)
    add_reviews(run)
    second = await engine.end_loop(run, Decisions(progress=["Repaired verified behavior"]), docker=docker)
    assert second["qualified"] and second["stop_reason"] is None
    await engine.begin_loop(run, docker=docker)
    add_reviews(run)
    third = await engine.end_loop(run, docker=docker)
    assert third["stop_reason"] == "quality_success"
    await engine.finish(run, docker=docker)


@pytest.mark.asyncio
async def test_missing_and_stale_reviews_never_pass(assessment):
    run, root, docker = assessment
    await engine.begin_loop(run, docker=docker)
    with pytest.raises(ValueError, match="active interaction"):
        state = load_json(run / "state.json")
        engine.record_review(run, Review(candidate_id=state["current"]["candidate_id"], role="product",
            target="target-01", synthetic_confidence=0, verdict_confidence=100, summary="No probes"))
    result = await engine.end_loop(run, docker=docker)
    assert not result["complete"] and not result["qualified"]
    await engine.begin_loop(run, docker=docker)
    (root / "deceive/marker.py").write_text("external_edit = True\n")
    with pytest.raises(ValueError, match="Candidate changed"):
        await engine.end_loop(run, docker=docker)
    await engine.finish(run, reason="cancelled", docker=docker)
    assert "incomplete" in (run / "dashboard.svg").read_text().lower()


@pytest.mark.asyncio
async def test_finish_requires_confirmation_and_current_candidate(assessment):
    run, root, docker = assessment
    await engine.begin_loop(run, docker=docker)
    add_reviews(run)
    await engine.end_loop(run, docker=docker)
    assert not (await engine.finish(run, docker=docker))["qualified"]
    await engine.resume(run, additional_loops=1)
    await engine.begin_loop(run, docker=docker)
    add_reviews(run)
    await engine.end_loop(run, docker=docker)
    assert (await engine.finish(run, docker=docker))["qualified"]
    (root / "deceive/marker.py").write_text("unassessed_repair = True\n")
    assert not (await engine.finish(run, docker=docker))["qualified"]


@pytest.mark.asyncio
async def test_allocation_conflict_is_retried_with_new_bindings(assessment, monkeypatch):
    run, _, docker = assessment
    original = engine.deploy
    attempts = []

    async def conflict(*args):
        attempts.append(True)
        if len(attempts) == 1:
            raise RuntimeError("Docker start failed: port is already allocated")
        return await original(*args)

    monkeypatch.setattr(engine, "deploy", conflict)
    await engine.begin_loop(run, docker=docker)
    assert len(attempts) == 2
    assert not load_json(run / "state.json")["current"]["targets"]["target-01"].get("error")
    await engine.finish(run, reason="cancelled", docker=docker)


def test_snapshot_preserves_omission_and_binary_assets(tmp_path):
    (tmp_path / "asset.bin").write_bytes(b"\x00\xff")
    profile = tmp_path / "profile.yaml"
    profile.write_text('id: fragment\nrequirements: {protocol: https, http_versions: ["2"], base_profile: demo-http, base_version: "1"}\n'
                       'behaviors: [{id: bytes, match: {path: /x}, reply: {body_file: asset.bin}}]\n')
    stage = tmp_path / "stage"
    stage.mkdir()
    path = stage_profile(str(profile), stage)
    staged = json.loads((stage / Path(path).name).read_text())
    assert "identity" not in staged and "fallback" not in staged
    assert (stage / Path(staged["behaviors"][0]["reply"]["body_file"]).name).read_bytes() == b"\x00\xff"


def test_snapshot_accepts_explicit_null_optional_requirements(tmp_path):
    profile = tmp_path / "profile.yaml"
    profile.write_text('id: nullable\nprotocol: http\nrequirements: null\n')
    stage = tmp_path / "stage"
    stage.mkdir()
    result = stage_profile(str(profile), stage)
    assert json.loads((stage / Path(result).name).read_text())["requirements"] is None


def test_image_identity_distinguishes_client_profile_and_server_changes(assessment, tmp_path):
    _, root, _ = assessment
    (root / "deceive/assessment").mkdir()
    client = root / "deceive/assessment/driver.py"
    client.write_text("client = 1\n")
    (root / "deceive/profiles").mkdir()
    profile = root / "deceive/profiles/profile.yaml"
    profile.write_text("id: one\nprotocol: http\n")
    snapshots = []
    for index in range(4):
        if index == 1:
            client.write_text("client = 2\n")
        elif index == 2:
            profile.write_text("id: two\nprotocol: http\n")
        elif index == 3:
            (root / "deceive/marker.py").write_text("server = 2\n")
        output = tmp_path / str(index)
        output.mkdir()
        snapshots.append(checkpoint(root, output))
    assert len({s["server_id"] for s in snapshots[:3]}) == 1
    assert snapshots[0]["client_id"] != snapshots[1]["client_id"]
    assert snapshots[2]["server_id"] != snapshots[3]["server_id"]


@pytest.mark.asyncio
async def test_verified_critical_findings_survive_a_panel_that_misses_them(assessment):
    run, _, docker = assessment
    await engine.begin_loop(run, docker=docker)
    add_reviews(run)
    state = load_json(run / "state.json")
    engine.record_review(run, Review(candidate_id=state["current"]["candidate_id"], role="product",
        target="target-01", synthetic_confidence=10, verdict_confidence=95, summary="Observed defect",
        findings=[{"id": "defect", "severity": "P1", "category": "identity_or_state",
                   "description": "Contradictory identity", "expected": "Consistent identity", "evidence": ["product"]}]))
    decisions = Decisions(findings={"product/target-01/defect": {
        "status": "verified", "rationale": "Reproduced", "evidence": ["product"]}})
    assert not (await engine.end_loop(run, decisions, docker=docker))["qualified"]
    await engine.begin_loop(run, docker=docker)
    add_reviews(run)
    result = await engine.end_loop(run, docker=docker)
    assert not result["qualified"]
    assert load_json(run / "state.json")["loops"][-1]["findings"][0]["verification"]["status"] == "verified"
    await engine.finish(run, docker=docker)


@pytest.mark.asyncio
async def test_group_review_without_every_service_has_a_coverage_gap(assessment):
    run, _, docker = assessment
    await engine.begin_loop(run, docker=docker)
    state = load_json(run / "state.json")
    entry = state["current"]["targets"]["target-01"]
    entry["endpoints"].append({"id": "service-2", "protocol": "ssh", "versions": ["1.1"]})
    write_json(run / "state.json", state)
    add_reviews(run)
    result = await engine.end_loop(run, docker=docker)
    assert not result["complete"] and not result["qualified"]
    target = load_json(run / "state.json")["loops"][-1]["targets"]["target-01"]
    assert not target["coverage"]["product"]["service-2"]
    await engine.finish(run, docker=docker)
