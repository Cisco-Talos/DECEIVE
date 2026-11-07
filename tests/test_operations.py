import json

import pytest
import yaml

from deceive.catalog import profiles, show
from deceive.cli import main
from deceive.config import load_profile
from deceive.vulnerability_catalog import bundled_vulnerabilities


@pytest.mark.parametrize("prefix,suffix", [(["--json"], []), ([], ["--json"])])
def test_catalog_result_envelope_and_vulnerability_inventory(capsys, prefix, suffix):
    assert main([*prefix, "profile", "list", "--vulnerabilities", *suffix]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["schema_version"] == 1 and result["operation"] == "profile.list"
    assert result["ok"] and result["exit_code"] == 0 and result["error"] is None
    assert {row["id"] for row in result["data"]["profiles"]} == set(bundled_vulnerabilities())
    assert {"sudo-2019-14287", "apache-2021-41773", "sshhole-2026-123158"} <= set(bundled_vulnerabilities())


def test_catalog_resolves_assets_baselines_and_rejects_conflicting_ids(tmp_path):
    (tmp_path / "payload.bin").write_bytes(b"\x00\xffnative")
    (tmp_path / "profile.yaml").write_text(yaml.safe_dump({"id": "download",
        "requirements": {"protocol": "https", "base_profile": "demo-http", "base_version": "1",
                         "http_versions": ["2", "3"]},
        "behaviors": [{"id": "download", "match": {"path": "/download"},
                       "reply": {"body_file": "payload.bin"}}]}))
    result = show("download", [tmp_path])
    assert result["effective_identity"]["hostname"] == "portal.build.example"
    assert "hostname" not in result["definition"].get("identity", {})
    assert result["definition"]["behaviors"][0]["reply"]["body_base64"] == "AP9uYXRpdmU="
    original = load_profile("demo-http").model_dump(mode="json")
    original["description"] = "Conflicting catalog definition"
    (tmp_path / "duplicate.yaml").write_text(yaml.safe_dump(original))
    with pytest.raises(ValueError, match="Conflicting profile"):
        profiles([tmp_path])


def test_json_validation_is_read_only_and_omits_account_secrets(tmp_path, capsys):
    config = tmp_path / "deployment.yaml"
    data = tmp_path / "not-created"
    config.write_text(yaml.safe_dump({"data_dir": str(data), "listeners": [
        {"protocol": "ssh", "profile": "sudo-2019-14287", "accounts": {"user1": "private-password"}}]}))
    assert main(["config", "validate", "--config", str(config), "--json"]) == 0
    output = capsys.readouterr().out
    assert "private-password" not in output and not data.exists()
    assert json.loads(output)["data"]["listeners"][0]["profiles"][0]["id"] == "sudo-2019-14287"
    assert main(["profile", "show", "missing", "--json"]) == 2
    failure = json.loads(capsys.readouterr().out)
    assert failure["operation"] == "profile.show" and not failure["ok"]
    assert failure["error"]["message"].startswith("Profile not found")


def test_parse_failure_and_foreground_json_do_not_start_a_server(capsys, monkeypatch):
    def forbidden(*args):
        pytest.fail("No listener should start")

    monkeypatch.setattr("deceive.cli.serve", forbidden)
    assert main(["profile", "show", "--json"]) == 2
    assert json.loads(capsys.readouterr().out)["error"]["code"] == "invalid_arguments"
    assert main(["serve", "--json"]) == 2
    assert "JSONL" in json.loads(capsys.readouterr().out)["error"]["message"]


def test_assessment_status_preserves_raw_output_and_opt_in_envelope(tmp_path, capsys):
    (tmp_path / "state.json").write_text(json.dumps({"run_id": "fixture", "current": None,
        "loops": [], "phase": "finished", "spec": {"limits": {}, "review_rubric": "evidence-v2"}}))
    assert main(["assess", "status", "--run", str(tmp_path)]) == 0
    raw = json.loads(capsys.readouterr().out)
    assert raw["run_id"] == "fixture" and "operation" not in raw
    assert main(["assess", "status", "--run", str(tmp_path), "--json"]) == 0
    envelope = json.loads(capsys.readouterr().out)
    assert envelope["operation"] == "assess.status" and envelope["data"] == raw


def test_empty_deployment_listing_does_not_create_state(tmp_path, capsys):
    directory = tmp_path / "absent"
    assert main(["deployment", "list", "--state-dir", str(directory), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["data"]["deployments"] == []
    assert not directory.exists()


def test_config_validation_is_live_by_default_and_offline_is_explicit(tmp_path, capsys, monkeypatch):
    from deceive.providers import ModelResult
    calls = []

    class Provider:
        def __init__(self, config, timeout, concurrency):
            calls.append(('initialize', config.model))

        async def complete(self, messages):
            calls.append(('complete', len(messages)))
            return ModelResult('ready')

        async def close(self):
            calls.append(('close',))

    monkeypatch.setattr('deceive.runtime.SDKProvider', Provider)
    path = tmp_path / 'deployment.yaml'
    path.write_text(yaml.safe_dump({'data_dir': str(tmp_path / 'not-created'),
        'providers': {'selected': {'kind': 'ollama', 'model': 'configured-model'}},
        'listeners': [{'name': 'ssh', 'protocol': 'ssh', 'profile': 'linux-device',
                       'provider': 'selected', 'host': '127.0.0.1', 'port': 0}]}))
    assert main(['config', 'validate', '--config', str(path), '--json']) == 0
    result = json.loads(capsys.readouterr().out)
    assert any(call[0] == 'complete' for call in calls)
    assert result['data']['validation']['verification'] == 'live-verified'
    assert not (tmp_path / 'not-created').exists()
    calls.clear()
    assert main(['config', 'validate', '--config', str(path), '--offline', '--json']) == 0
    result = json.loads(capsys.readouterr().out)
    assert result['data']['validation']['verification'] == 'offline-valid'
    assert not calls
