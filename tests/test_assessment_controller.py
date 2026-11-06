import json
import base64
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET

import pytest

from deceive.assessment import engine
from deceive.assessment.dashboard import render
from deceive.assessment.models import Decisions, Review
from deceive.assessment.workspace import checkpoint, load_json, prepare, spec_identity, stage_profile, write_json


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
    spec.write_text('schema_version: 1\nreview_rubric: evidence-v2\ntargets: [{name: web, profiles: [demo-http]}]\npolicy: {mode: fixed, max_loops: 20}\n')
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
                 "calibration": bool(target.control), "target_name": target.name, "stage": str(stage),
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
                "version": "1.1",
                "action": {"operation": "request", "endpoint": "service-1", "parameters": {}}, "facts": {"status": 200}}) + "\n")
        engine.record_review(run, Review(candidate_id=current["candidate_id"], role=role,
            target="target-01", synthetic_confidence=100-score, verdict_confidence=70,
            summary="Active mock review", score_basis={"band": "no_material_tell",
                "observations": ["Deterministic fixture exercised"], "evidence": [role],
                "coverage_limits": "Mock orchestration only, not a live realism result"}))


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
        assert not result["qualified"] and result['assessment_status'] == 'legacy_unvalidated', result
        assert result["stop_reason"] == ("count_complete" if number == 20 else None)
    assert subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"]) == head
    assert "preserve me" in (root / "deceive/marker.py").read_text()
    assert len(load_json(run / "state.json")["loops"]) == 20
    final = await engine.finish(run, docker=docker)
    assert not final["qualified"] and final["status"] == "count_complete"
    ET.parse(run / "dashboard.svg")
    assert "rolling5" in (run / "dashboard.svg").read_text()


@pytest.mark.asyncio
async def test_failed_gate_repairs_and_candidate_freshness(assessment, monkeypatch):
    run, root, docker = assessment
    state = load_json(run / "state.json")
    state["spec"]["policy"]["mode"] = "until"
    state['assessment_definition_id'] = spec_identity(state['spec'])
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
    assert not second["qualified"] and second['targets']['target-01']['correctness'] == 'passed'
    await engine.begin_loop(run, docker=docker)
    add_reviews(run)
    third = await engine.end_loop(run, docker=docker)
    assert third["stop_reason"] is None  # Legacy scalar reports cannot certify realism.
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
    assert not (await engine.finish(run, docker=docker))["qualified"]
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
        score_basis={"band": "no_material_tell", "observations": ["Fixture regression"],
                     "evidence": ["product"], "coverage_limits": "Mock orchestration"},
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


@pytest.mark.asyncio
async def test_new_rubric_requires_a_captured_score_basis(assessment):
    run, _, docker = assessment
    await engine.begin_loop(run, docker=docker)
    add_reviews(run)
    state = load_json(run / "state.json")
    report = Review(candidate_id=state["current"]["candidate_id"], role="product", target="target-01",
                    synthetic_confidence=10, verdict_confidence=70, summary="No basis")
    with pytest.raises(ValueError, match="rubric"):
        engine.record_review(run, report)
    report = Review.model_validate(report.model_dump() | {"score_basis": {
        "band": "no_material_tell", "observations": ["Not my captured evidence"],
        "evidence": ["another-role"], "coverage_limits": "Fixture"}})
    with pytest.raises(ValueError, match="Score basis references"):
        engine.record_review(run, report)
    await engine.finish(run, docker=docker)


@pytest.mark.asyncio
async def test_review_must_cover_every_declared_http_version(assessment):
    run, _, docker = assessment
    await engine.begin_loop(run, docker=docker)
    state = load_json(run / "state.json")
    state["current"]["targets"]["target-01"]["endpoints"][0]["versions"] = ["1.1", "2", "3"]
    write_json(run / "state.json", state)
    add_reviews(run)
    result = await engine.end_loop(run, docker=docker)
    assert not result["complete"] and not result["qualified"]
    target = load_json(run / "state.json")["loops"][-1]["targets"]["target-01"]
    assert target["protocol_coverage"]["product"]["service-1"] == {"1.1": True, "2": False, "3": False}
    await engine.finish(run, docker=docker)


def v3_fixture(run, monkeypatch):
    from test_assessment_quality import fixture_target

    data = [fixture_target('ordinary'), fixture_target('major-control', 'major'),
            fixture_target('subtle-control', 'subtle')]
    state = load_json(run / 'state.json')
    state['spec'].update(review_rubric='evidence-v3', targets=[t.model_dump(mode='json') for t, *_ in data])
    state['assessment_definition_id'] = spec_identity(state['spec'])
    write_json(run / 'state.json', state)
    monkeypatch.setattr(engine, 'audit', lambda *args: {'status': 'passed', 'observations': 30})
    return data


def research_fixture(run, monkeypatch):
    from deceive.assessment.research import Dossier
    data = v3_fixture(run, monkeypatch)
    for target, _, _, reviews in data:
        target.research = Dossier.model_validate({'profile_id': 'demo-http', 'version': '1',
            'subject': 'Synthetic deterministic test fixture, not realism evidence', 'kind': 'fictional',
            'sources': [{'id': 'fixture-doc', 'kind': 'standard', 'title': 'Fake reference',
                'url': 'https://example.invalid/fixture', 'retrieved': '2026-11-04',
                'facts': ['Synthetic fixture expects result ok.']}],
            'criteria': [{'id': 'fixture-comparison', 'roles': list(reviews[i]['role'] for i in range(4)),
                'sources': ['fixture-doc'], 'expectation': 'Compare fake result metadata.',
                'comparisons': ['Deterministic fixture workflows only.']}]})
        for review in reviews:
            review.update(schema_version=3, confidence_reason='Fake report exercises validation; no live realism judgment or calibrated probability.')
            for rating in review['ratings'].values():
                rating['comparison'] = {'source_ids': ['fixture-doc'],
                    'criterion_ids': ['fixture-comparison'],
                    'rationale': 'Synthetic comparison metadata exercises provenance validation with fake reports only.',
                    'limitations': 'No independent agent or real product is evaluated by this test fixture.'}
    state = load_json(run / 'state.json')
    state['spec'].update(review_rubric='research-v4', targets=[t.model_dump(mode='json') for t, *_ in data])
    state['assessment_definition_id'] = spec_identity(state['spec'])
    write_json(run / 'state.json', state)
    return data


def add_v3_reviews(run, data, *, miss_control=False):
    state = load_json(run / 'state.json')
    current = state['current']
    directory = run / current['directory']
    for index, (_, _, observations, reviews) in enumerate(data, 1):
        handle = f'target-{index:02d}'
        for observation in observations:
            observation.update(target=handle, candidate_id=current['candidate_id'])
        with (directory / 'observations.jsonl').open('a') as stream:
            stream.write(''.join(json.dumps(o) + '\n' for o in observations))
        for review in reviews:
            review.update(target=handle, candidate_id=current['candidate_id'])
            if miss_control and index == 3:
                # An over-generous reviewer can submit this; the controller must refuse qualification.
                review['findings'] = []
                for rating in review['ratings'].values():
                    rating['rating'] = 4
            engine.record_review(run, Review.model_validate(review))


@pytest.mark.asyncio
async def test_public_goals_expose_execution_scope_without_private_assertions(assessment, monkeypatch):
    run, _, docker = assessment
    v3_fixture(run, monkeypatch)
    state = load_json(run / 'state.json')
    goal = state['spec']['targets'][0]['coverage'][0]
    goal.update(every_version=True, every_service=False, same_session=True, ordered=False)
    goal['steps'][0]['select'].append({'field': 'action.parameters.method', 'equals': 'GET'})
    state['assessment_definition_id'] = spec_identity(state['spec'])
    write_json(run / 'state.json', state)
    public = await engine.begin_loop(run, docker=docker)
    exposed = public['targets']['target-01']['coverage_goals'][0]
    assert exposed['every_version'] is True
    assert exposed['every_service'] is False
    assert exposed['same_session'] is True
    assert exposed['different_sessions'] is False
    assert exposed['ordered'] is False
    assert exposed['required_methods'] == ['GET']
    assert not {'steps', 'select', 'expect'}.intersection(exposed)
    await engine.finish(run, docker=docker)


@pytest.mark.asyncio
async def test_research_complete_repair_and_two_round_confirmation(assessment, monkeypatch):
    run, root, docker = assessment
    data = research_fixture(run, monkeypatch)
    state = load_json(run / 'state.json')
    state['spec']['policy']['mode'] = 'until'
    state['assessment_definition_id'] = spec_identity(state['spec'])
    write_json(run / 'state.json', state)
    await engine.begin_loop(run, docker=docker)
    add_v3_reviews(run, data)
    state = load_json(run / 'state.json')
    state['current']['correctness']['target-01'] = {'status': 'failed'}
    write_json(run / 'state.json', state)
    assert not (await engine.end_loop(run, docker=docker))['qualified']
    with (root / 'deceive/marker.py').open('a') as stream:
        stream.write('repair = True\n')
    for number in range(2):
        await engine.begin_loop(run, docker=docker)
        add_v3_reviews(run, data)
        result = await engine.end_loop(run, docker=docker)
        assert result['qualified'] and result['assessment_status'] == 'assessed', result
        assert result['stop_reason'] == ('quality_success' if number else None)
    assert (await engine.finish(run, docker=docker))['qualified']
    (root / 'deceive/marker.py').write_text('unassessed_change = True\n')
    assert not (await engine.finish(run, docker=docker))['qualified']


@pytest.mark.asyncio
async def test_v3_missed_controls_create_gaps_not_passing_scores(assessment, monkeypatch):
    run, _, docker = assessment
    data = research_fixture(run, monkeypatch)
    public = await engine.begin_loop(run, docker=docker)
    assert 'major-control' not in json.dumps(public) and 'known-gap' not in json.dumps(public)
    assert 'Private known defect' not in json.dumps(public)
    add_v3_reviews(run, data, miss_control=True)
    result = await engine.end_loop(run, docker=docker)
    assert not result['qualified'] and not result['complete']
    assert result['assessment_status'] == 'insufficiently_assessed'
    assert len(result['calibration_results']['missing']) == 4
    latest = load_json(run / 'state.json')['loops'][-1]
    assert latest['targets']['target-01']['median'] is None
    assert latest['targets']['target-01']['provisional_scores']['product'] == 100
    await engine.finish(run, docker=docker)


@pytest.mark.asyncio
async def test_legacy_v3_cannot_claim_research_realism(assessment, monkeypatch):
    run, _, docker = assessment
    data = v3_fixture(run, monkeypatch)
    await engine.begin_loop(run, docker=docker)
    add_v3_reviews(run, data)
    result = await engine.end_loop(run, docker=docker)
    assert result['complete']
    assert not result['qualified'] and result['assessment_status'] == 'legacy_unvalidated'
    assert not (await engine.finish(run, docker=docker))['qualified']


@pytest.mark.asyncio
async def test_v3_cannot_import_v2_reports_or_foreign_criterion_evidence(assessment, monkeypatch):
    run, _, docker = assessment
    data = v3_fixture(run, monkeypatch)
    await engine.begin_loop(run, docker=docker)
    with pytest.raises(ValueError, match='schema'):
        add_reviews(run)
    add_v3_reviews(run, data)
    review = data[0][3][0]
    review['ratings']['negotiation']['evidence'][0] = data[0][2][-1]['interaction_id']
    with pytest.raises(ValueError, match='Criterion references'):
        engine.record_review(run, Review.model_validate(review))
    await engine.finish(run, docker=docker)


@pytest.mark.asyncio
async def test_prepared_coverage_and_thresholds_cannot_be_edited_to_pass(assessment):
    run, _, docker = assessment
    await engine.begin_loop(run, docker=docker)
    add_reviews(run)
    state = load_json(run / 'state.json')
    state['spec']['policy']['minimum_realism'] = 0
    write_json(run / 'state.json', state)
    with pytest.raises(ValueError, match='Frozen assessment'):
        await engine.end_loop(run, docker=docker)
    assert not (await engine.finish(run, docker=docker))['qualified']


@pytest.mark.asyncio
async def test_v3_goal_reference_errors_are_repairable_before_closing_loop(assessment, monkeypatch):
    run, _, docker = assessment
    data = v3_fixture(run, monkeypatch)
    await engine.begin_loop(run, docker=docker)
    add_v3_reviews(run, data)
    report = data[0][3][0]
    report['ratings']['wire_fidelity']['coverage'].append('product-positive')
    with pytest.raises(ValueError, match='goal IDs assigned to your role'):
        engine.record_review(run, Review.model_validate(report))
    report['ratings']['wire_fidelity']['coverage'].remove('product-positive')
    report['ratings']['wire_fidelity']['coverage'] = []
    with pytest.raises(ValueError, match='Missing assigned goals'):
        engine.record_review(run, Review.model_validate(report))
    report['ratings']['wire_fidelity']['coverage'] = ['protocol-positive']
    engine.record_review(run, Review.model_validate(report))
    assert load_json(run / 'state.json')['phase'] == 'active'
    await engine.finish(run, docker=docker)


@pytest.mark.asyncio
async def test_schema2_refuses_premature_closure_and_preserves_live_attempt(assessment, monkeypatch):
    run, _, docker = assessment
    data = research_fixture(run, monkeypatch)
    state = load_json(run / 'state.json')
    state['spec']['schema_version'] = 2
    state['assessment_definition_id'] = spec_identity(state['spec'])
    write_json(run / 'state.json', state)
    await engine.begin_loop(run, docker=docker)
    with pytest.raises(ValueError, match='audit'):
        await engine.end_loop(run, docker=docker)
    assert load_json(run / 'state.json')['phase'] == 'active'
    assert not docker.stopped
    # A diagnostic partial close is explicit and never qualifies.
    result = await engine.end_loop(run, docker=docker, incomplete_reason='Fixture has no reviewer observations; preserve incomplete attempt', incomplete_kind='incomplete_review')
    assert not result['complete'] and not result['qualified']


def register_fixture_plans(run, data):
    from deceive.assessment.workflow import record_plan
    from deceive.assessment.models import ProbePlan
    state=load_json(run/'state.json')
    for index,(_,_,observations,reviews) in enumerate(data,1):
        for role in state['spec']['roles']:
            actions=[o['action'] | {'parameters':o['action']['parameters'] | {'version':'1.1'}}
                     for o in observations if o['role']==role]
            result=record_plan(run,ProbePlan(candidate_id=state['current']['candidate_id'],
                role=role,target=f'target-{index:02d}',reserve_actions=1,actions=actions))
            assert result['ready'],result


@pytest.mark.asyncio
async def test_schema2_audit_repairs_citations_before_closing(assessment, monkeypatch):
    from deceive.assessment.workflow import review_audit
    run,_,docker=assessment
    data=research_fixture(run,monkeypatch)
    state=load_json(run/'state.json');state['spec']['schema_version']=2
    state['assessment_definition_id']=spec_identity(state['spec']);write_json(run/'state.json',state)
    await engine.begin_loop(run,docker=docker)
    register_fixture_plans(run,data)
    add_v3_reviews(run,data)
    assert review_audit(run)['ready']
    state=load_json(run/'state.json');path=run/state['current']['reviews']['protocol/target-01']
    original=load_json(path);bad=json.loads(json.dumps(original))
    bad['ratings']['wire_fidelity']['evidence']=[
        'ordinary-protocol-baseline-0','ordinary-protocol-repeat-0']
    engine.record_review(run,Review.model_validate(bad))
    assert not review_audit(run)['ready']
    with pytest.raises(ValueError,match='audit'):
        await engine.end_loop(run,docker=docker)
    assert not docker.stopped
    engine.record_review(run,Review.model_validate(original))
    assert review_audit(run)['ready']
    assert (await engine.end_loop(run,docker=docker))['complete']


@pytest.mark.asyncio
async def test_audit_distinguishes_recovered_client_errors_from_connection_interruptions(assessment, monkeypatch):
    from deceive.assessment.workflow import review_audit
    run,_,docker=assessment
    data=research_fixture(run,monkeypatch)
    state=load_json(run/'state.json');state['spec']['schema_version']=2
    state['assessment_definition_id']=spec_identity(state['spec']);write_json(run/'state.json',state)
    await engine.begin_loop(run,docker=docker)
    register_fixture_plans(run,data);add_v3_reviews(run,data)
    state=load_json(run/'state.json');c=state['current']
    path=run/c['directory']/'observations.jsonl'
    event=data[0][2][0] | {'candidate_id':c['candidate_id'],'target':'target-01'}
    with path.open('a') as stream:
        stream.write(json.dumps(event | {'interaction_id':'bad-client','error':'ValueError: unsupported client operation'})+'\n')
        stream.write(json.dumps(event | {'interaction_id':'unavailable','error':'ConnectionRefusedError: local service unavailable'})+'\n')
    result=review_audit(run)
    assert result['ready']  # Complete fresh evidence already proves recovery; failures cannot establish scores.
    issues=result['targets']['target-01']['issues']
    assert {i['category'] for i in issues}=={'harness_error','infrastructure_interruption'}
    assert all(i['blocking'] is False for i in issues)
    await engine.finish(run,docker=docker)
