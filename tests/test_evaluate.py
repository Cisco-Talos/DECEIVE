from importlib.resources import files
import json

import pytest
import yaml

from deceive.evaluate import evaluate


@pytest.mark.asyncio
@pytest.mark.parametrize("version", ["1.1", "2", "3"])
async def test_real_listener_evaluation_and_fingerprints(tmp_path, version):
    suite = yaml.safe_load(files("deceive").joinpath("acceptance/demo-http.yaml").read_text())
    suite["http_version"] = version
    path = tmp_path / "suite.yaml"
    path.write_text(yaml.safe_dump(suite))
    report = await evaluate("demo-http", path, tmp_path / "report")
    assert report["passed"]
    assert report["passed_cases"] == report["total_cases"] == 5
    assert len(report["suite_fingerprint"]) == 64
    assert (tmp_path / "report/summary.txt").read_text().startswith("PASS")
    assert all(step["version"] == version for case in report["cases"] for run in case["runs"] for step in run)
    assert not report["live_model"]


@pytest.mark.asyncio
async def test_failure_report_and_model_opt_in(tmp_path):
    suite = tmp_path / "suite.yaml"
    suite.write_text("id: failing\ncases:\n  - id: incorrect\n    steps:\n      - path: /\n        expect: {status: 500}\n")
    report = await evaluate("demo-http", suite, tmp_path / "report")
    assert not report["passed"]
    assert "status 200" in report["cases"][0]["runs"][0][0]["errors"][0]
    assert json.loads((tmp_path / "report/results.json").read_text())["passed"] is False
    with pytest.raises(ValueError, match="live-model"):
        await evaluate("linux-ssh", suite, tmp_path / "live")
    with pytest.raises(ValueError, match="already exists"):
        await evaluate("demo-http", suite, tmp_path / "report")


@pytest.mark.asyncio
async def test_ssh_sequences_state_and_reconnect_isolation(tmp_path):
    from deceive.config import load_profile

    profile = load_profile("linux-ssh")
    profile.fallback = "reject"
    path = tmp_path / "ssh.yaml"
    path.write_text(yaml.safe_dump(profile.model_dump(mode="json")))
    suite = tmp_path / "sequence.yaml"
    suite.write_text('''id: ssh-sequence
cases:
  - id: private-cwd
    steps:
      - command: hostname
        expect: {body: "build-node-03\\n"}
      - command: cd /etc
        expect: {body: "", state: {cwd: /etc}}
      - command: pwd
        new_session: true
        expect: {body: "/home/guest\\n"}
      - command: exit
        expect: {body: "", exit_status: 0}
''')
    report = await evaluate(str(path), suite, tmp_path / "report")
    assert report["passed"], report


def test_authoring_refinement_preserves_agreed_suite(tmp_path):
    from deceive.cli import main

    profile = tmp_path / "profile.yaml"
    suite = tmp_path / "acceptance.yaml"
    original = "id: authored\nprotocol: http\nbehaviors:\n  - id: page\n    reply: {body: candidate}\n"
    profile.write_text(original)
    suite.write_text("id: frozen\ncases:\n  - id: exact\n    steps:\n      - path: /\n        expect: {body: accepted}\n")
    before = suite.read_bytes()
    assert main(["profile", "validate", str(profile)]) == 0
    assert main(["profile", "evaluate", str(profile), "--suite", str(suite),
                 "--report-dir", str(tmp_path / "first")]) == 1
    profile.write_text(original.replace("candidate", "accepted"))
    assert main(["profile", "evaluate", str(profile), "--suite", str(suite),
                 "--report-dir", str(tmp_path / "second")]) == 0
    first = json.loads((tmp_path / "first/results.json").read_text())
    second = json.loads((tmp_path / "second/results.json").read_text())
    assert first["suite_fingerprint"] == second["suite_fingerprint"]
    assert first["profile_fingerprint"] != second["profile_fingerprint"]
    assert suite.read_bytes() == before
