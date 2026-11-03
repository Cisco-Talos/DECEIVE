from base64 import b64decode
from importlib.resources import files
import asyncio
import io
import json
from datetime import date
from pathlib import Path

import asyncssh
import httpx
import pytest

from deceive.config import fingerprint, load_deployment, load_profile, read_yaml
from deceive.evaluate import Suite, evaluate
from deceive.models import Behavior
from deceive.vulnerabilities import CVE_HANDLERS
from deceive.vulnerability_catalog import approval_for, bundled_vulnerabilities


def test_bundled_cves_have_reviewed_nonempty_acceptance_contracts():
    names = bundled_vulnerabilities()
    assert names
    exercised = set()
    root = Path(__file__).resolve().parents[1]
    for name in names:
        profile = load_profile(name)
        assert profile.id == name
        exercised.update(b.kind for b in profile.behaviors if b.kind in CVE_HANDLERS)
        path = Path(str(files("deceive").joinpath("acceptance", name + ".yaml")))
        assert path.is_file(), f"{name}: acceptance suite required before shipping"
        raw = read_yaml(path)
        suite = Suite.model_validate(raw)
        assert suite.id == name and suite.references
        assert any(c.group == "held_out" for c in suite.cases), f"{name}: variation cases required"
        approval = approval_for(name)
        assert approval["schema_version"] == 1 and approval["approval"].strip()
        date.fromisoformat(approval["approved_on"])
        criteria = root / approval["criteria"]
        assert criteria.resolve().is_relative_to(root) and criteria.is_file()
        assert fingerprint(raw) == approval["suites"][name], f"{name}: agreed suite changed"
    assert exercised == set(CVE_HANDLERS), "Every registered CVE handler needs a bundled profile and suite"


def test_sudo_v2_amendment_preserves_original_agreement_and_criteria():
    history = files("deceive").joinpath("acceptance/history")
    old = json.loads(history.joinpath("reference-v1-approval.json").read_text())
    legacy = read_yaml(Path(str(history.joinpath("sudo-2019-14287-v1.yaml"))))
    assert fingerprint(legacy) == old["suites"]["sudo-2019-14287"] == "70e537d51458f9b372493c4bb86c792a8d2b67de5348f13e565190add298047a"
    assert old["approved_on"] == "2026-11-01" and "apache-2021-41773" in old["suites"]
    approval = approval_for("sudo-2019-14287")
    assert approval["profile_version"] == approval["suite_version"] == "2"
    assert load_profile("sudo-2019-14287").version == "2"


@pytest.mark.asyncio
@pytest.mark.parametrize("name", bundled_vulnerabilities())
async def test_approved_reference_acceptance_suite(tmp_path, name):
    suite = files("deceive").joinpath("acceptance", name + ".yaml")
    report = await evaluate(name, suite, tmp_path / "report")
    approval = approval_for(name)
    assert report["suite_fingerprint"] == approval["suites"][name]
    assert report["passed"], report
    assert report["passed_cases"] == report["total_cases"]
    assert report["held_out_pass_rate"] == 1.0
    summaries = [event for case in report["cases"] for event in case.get("telemetry", [])
                 if event["message"] == "Session summary"]
    assert summaries and all(event["judgement"] == "UNKNOWN" for event in summaries)


@pytest.mark.asyncio
async def test_apache_preserves_encoded_path_and_never_reads_host_files(runtime_factory, tmp_path):
    profile = load_profile("apache-2021-41773")
    runtime = await runtime_factory(profile=profile)
    port = next(iter(runtime.servers.values())).endpoints[0]["port"]
    secret = tmp_path / "host-only-secret"
    secret.write_text("PRIVATE-HOST-DATA")
    traversal = "/cgi-bin/" + ".%2e/" * 4
    async with httpx.AsyncClient(base_url=f"http://127.0.0.1:{port}", trust_env=False) as client:
        response = await client.get(traversal + "etc/passwd")
        assert response.status_code == 200 and "archive:x:" in response.text
        unknown = await client.get(traversal + str(secret).lstrip("/"))
        assert unknown.status_code == 404
        assert "PRIVATE-HOST-DATA" not in unknown.text
    records = [json.loads(line) for line in runtime.test_stream.getvalue().splitlines()]
    input_event = next(r for r in records if r["message"] == "User input")
    request = json.loads(b64decode(input_event["details"]))
    assert b64decode(request["raw_path"]) == (traversal + "etc/passwd").encode()
    assert "PRIVATE-HOST-DATA" not in runtime.test_stream.getvalue()


@pytest.mark.asyncio
async def test_sudo_uses_virtual_identity_and_rejects_shell_execution(runtime_factory, tmp_path):
    runtime = await runtime_factory("ssh", profile=load_profile("sudo-2019-14287"))
    port = next(iter(runtime.servers.values())).endpoints[0]["port"]
    marker = tmp_path / "must-not-be-created"
    async with asyncssh.connect("127.0.0.1", port=port, username="guest", known_hosts=None) as connection:
        result = await connection.run(f"sudo -u#-1 /bin/sh -c 'touch {marker}'")
        assert result.exit_status == 1
        assert "not allowed to execute" in result.stdout
    assert not marker.exists()
    async with asyncssh.connect("127.0.0.1", port=port, username="intruder", password="x", known_hosts=None) as connection:
        result = await connection.run("sudo -u#-1 id -u")
        assert result.exit_status == 1 and "not in the sudoers" in result.stdout


@pytest.mark.asyncio
@pytest.mark.parametrize(("command", "rendered"), [
    ("sudo -u#-1 /bin/sh", "/bin/sh"),
    ("sudo -u#-1 id --user", "/usr/bin/id --user"),
    ("sudo --user='#4294967295' /usr/bin/id -ru", "/usr/bin/id -ru"),
])
async def test_sudo_denial_uses_virtual_stock_style_facts(runtime_factory, command, rendered):
    profile = load_profile("sudo-2019-14287")
    profile.identity.hostname = "audit-host-09"
    profile.files["/etc/hostname"] = "audit-host-09\n"
    runtime = await runtime_factory("ssh", profile=profile)
    port = next(iter(runtime.servers.values())).endpoints[0]["port"]
    async with asyncssh.connect("127.0.0.1", port=port, username="guest", known_hosts=None) as client:
        result = await client.run(command)
    target = "#4294967295" if "4294967295" in command else "#-1"
    assert result.exit_status == 1
    assert result.stdout == (f"Sorry, user guest is not allowed to execute '{rendered}' "
                             f"as {target} on audit-host-09.\n")
    assert "simulat" not in result.stdout.lower()


def test_cve_options_are_validated_before_listening():
    from deceive.behaviors import validate_behavior

    with pytest.raises(ValueError):
        validate_behavior(Behavior(id="bad", kind="apache-2021-41773", options={"alias_prefix": "../"}))
    with pytest.raises(ValueError):
        validate_behavior(Behavior(id="bad", kind="sudo-2019-14287", options={"execute": True}))
    profile = load_profile("apache-2021-41773")
    profile.http_versions = ["1.1", "3"]
    with pytest.raises(ValueError, match="HTTP/1.1 only"):
        validate_behavior(profile.behaviors[0], profile)


@pytest.mark.asyncio
async def test_reference_deployment_runs_both_protocols_in_one_process(tmp_path):
    from deceive.runtime import Runtime
    from deceive.telemetry import Telemetry

    path = Path(__file__).resolve().parents[1] / "examples/reference-deployment.yaml"
    config = load_deployment(path)
    config.data_dir = tmp_path
    for listener in config.listeners:
        listener.host, listener.port = "127.0.0.1", 0
    stream = io.StringIO()
    runtime = Runtime(config, telemetry=Telemetry("reference", stream=stream))
    try:
        await runtime.start()
        assert set(runtime.servers) == {"sudo", "apache"}

        async def ssh_probe():
            port = runtime.servers["sudo"].endpoints[0]["port"]
            async with asyncssh.connect("127.0.0.1", port=port, username="guest", known_hosts=None) as connection:
                result = await connection.run("sudo -u#-1 id -u")
                assert result.stdout == "0\n"

        async def http_probe():
            port = runtime.servers["apache"].endpoints[0]["port"]
            async with httpx.AsyncClient(trust_env=False) as client:
                result = await client.get(f"http://127.0.0.1:{port}/cgi-bin/" + ".%2e/" * 4 + "etc/passwd")
                assert result.status_code == 200 and "archive:x:" in result.text

        await asyncio.gather(ssh_probe(), http_probe())
    finally:
        await runtime.close()
    records = [json.loads(line) for line in stream.getvalue().splitlines()]
    summaries = [record for record in records if record["message"] == "Session summary"]
    assert len(summaries) == 2
    assert len({record["task_name"] for record in summaries}) == 2
    assert {record["protocol_instance"] for record in summaries} == {"sudo", "apache"}
