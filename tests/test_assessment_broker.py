import asyncio
import time

import pytest

from deceive.assessment.broker import Broker
from deceive.assessment.drivers import Drivers
from deceive.assessment.models import ProbeAction
from deceive.assessment.workspace import load_json, write_json


@pytest.mark.asyncio
async def test_broker_persists_budget_deadline_and_attribution(tmp_path):
    directory = tmp_path / "loop"
    directory.mkdir()
    write_json(tmp_path / "state.json", {"spec": {
        "schema_version": 1,
        "targets": [{"name": "web", "profiles": ["demo-http"]}],
        "limits": {"per_role_target": 1}}, "started_epoch": time.time(), "current": {
        "directory": "loop", "candidate_id": "candidate", "targets": {"target-01": {
            "endpoints": [{"id": "service-1", "protocol": "http"}]}}}})
    broker = Broker(tmp_path)

    async def execute(*args):
        return {"version": "1.1", "body_base64": "", "facts": {"status": 200}}

    broker.drivers.execute = execute
    try:
        observed = await broker.probe("product", "target-01", ProbeAction(operation="request"))
        assert observed["candidate_id"] == "candidate" and observed["role"] == "product"
        assert load_json(directory / "probe-budget.json")["product/target-01"]["count"] == 1
        with pytest.raises(ValueError, match="budget exhausted"):
            await broker.probe("product", "target-01", ProbeAction(operation="request"))
        broker.budget["attacker/target-01"] = {"count": 0, "started": time.time() - 601}
        with pytest.raises(ValueError, match="deadline"):
            await broker.probe("attacker", "target-01", ProbeAction(operation="request"))
        with pytest.raises(ValueError, match="Unknown target"):
            await broker.probe("product", "outside", ProbeAction(operation="request"))
    finally:
        await broker.drivers.close()


@pytest.mark.asyncio
async def test_driver_timeout_and_cancellation_close_affected_session():
    class Slow:
        def __init__(self):
            self.closed = []

        async def execute(self, endpoint, action, key):
            if action.operation == "close":
                self.closed.append(key)
                return {}
            await asyncio.Event().wait()

    drivers = Drivers()
    slow = Slow()
    drivers.registry["test"] = slow
    try:
        with pytest.raises(TimeoutError):
            await drivers.execute({"protocol": "test", "timeout": 0.01},
                                  ProbeAction(operation="wait"), ("deadline",))
        pending = asyncio.create_task(drivers.execute({"protocol": "test"},
                                      ProbeAction(operation="wait"), ("cancel",)))
        await asyncio.sleep(0)
        pending.cancel()
        with pytest.raises(asyncio.CancelledError):
            await pending
        assert slow.closed == [("deadline",), ("cancel",)]
    finally:
        await drivers.close()
