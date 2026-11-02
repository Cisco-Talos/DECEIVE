import base64
from importlib.resources import files

import pytest

from deceive.assessment.drivers import Drivers
from deceive.assessment.models import ProbeAction
from deceive.config import load_profile
from deceive.evaluate import evaluate_external


def endpoint(runtime, protocol, versions):
    endpoints = next(iter(runtime.servers.values())).endpoints
    return {"protocol": protocol, "versions": versions, "ports": {
        e["transport"]: {"host": e["port"]} for e in endpoints}, "username": "guest", "password": ""}


@pytest.mark.asyncio
@pytest.mark.parametrize("version", ["1.1", "2", "3"])
async def test_driver_http_negotiation_binary_and_path_boundary(runtime_factory, version):
    protocol = "http" if version == "1.1" else "https"
    runtime = await runtime_factory(protocol, versions=[version])
    driver = Drivers()
    try:
        result = await driver.execute(endpoint(runtime, protocol, [version]),
            ProbeAction(operation="request", parameters={"path": "/download"}), ("role", "target", "s"))
        assert result["version"] == version and base64.b64decode(result["body_base64"]) == b"\x00\xff\x80A"
        with pytest.raises(ValueError, match="target-relative"):
            await driver.execute(endpoint(runtime, protocol, [version]),
                ProbeAction(operation="request", parameters={"path": "https://example.com/"}), ("x",))
    finally:
        await driver.close()


@pytest.mark.asyncio
async def test_driver_ssh_real_session_and_external_accepted_assertions(runtime_factory):
    runtime = await runtime_factory("ssh", profile=load_profile("sudo-2019-14287"))
    driver = Drivers()
    target = endpoint(runtime, "ssh", ["1.1"])

    async def execute(action):
        parsed = ProbeAction.model_validate(action)
        return await driver.execute(target, parsed, ("acceptance", parsed.session or "one-off"))

    try:
        report = await evaluate_external(files("deceive").joinpath("acceptance/sudo-2019-14287.yaml"),
                                         "ssh", "ssh", execute)
        assert report["external_passed"], report
        assert not report["passed"]  # Explicit protected variants still need separate deployments.
        assert any(c["backend"] == "requires_variant" for c in report["cases"])
    finally:
        await driver.close()


@pytest.mark.asyncio
async def test_driver_bounded_wire_operations(runtime_factory):
    runtime = await runtime_factory("https", versions=["2", "3"])
    driver = Drivers()
    target = endpoint(runtime, "https", ["2", "3"])
    try:
        rejected = await driver.execute(target, ProbeAction(operation="h2_method", parameters={
            "method": "GET\r\nX-Probe: local"}), ("wire",))
        assert rejected["facts"]["termination_code"] == 1
        ordinary = await driver.execute(target, ProbeAction(operation="h2_resets"), ("wire",))
        assert ordinary["facts"]["status"] == 200
        fin = await driver.execute(target, ProbeAction(operation="h3_fin", parameters={
            "content_length": 3, "body": ""}), ("wire",))
        assert fin["facts"]["termination_code"] == 270
        valid = await driver.execute(target, ProbeAction(operation="h3_fin", parameters={
            "content_length": 2, "body": "ab"}), ("wire",))
        assert valid["facts"]["status"] == 200
    finally:
        await driver.close()


@pytest.mark.asyncio
async def test_external_acceptance_preserves_optional_held_out_semantics(tmp_path):
    suite = tmp_path / "suite.yaml"
    suite.write_text('id: optional\ncases:\n'
                     '  - id: required\n    steps: [{path: /, expect: {status: 200}}]\n'
                     '  - id: variation\n    group: held_out\n'
                     '    steps: [{path: /other, expect: {status: 404}}]\n')

    async def execute(action):
        return {"version": "1.1", "facts": {"status": 200}}

    report = await evaluate_external(suite, "http", "1.1", execute)
    assert report["external_passed"]
    suite.write_text(suite.read_text() + 'held_out_min_pass_rate: 1.0\n')
    assert not (await evaluate_external(suite, "http", "1.1", execute))["external_passed"]
