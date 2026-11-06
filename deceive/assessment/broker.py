"""Private Unix-socket probe broker, preserving live protocol sessions between CLI calls."""
from __future__ import annotations

import argparse
import asyncio
import json
import os
from pathlib import Path
import time
import uuid

from deceive.assessment.drivers import Drivers
from deceive.assessment.models import Observation, ProbeAction, Spec
from deceive.assessment.workspace import load_json, now, write_json


class Broker:
    def __init__(self, run: Path):
        self.run = run
        self.state = load_json(run / "state.json")
        self.current = self.state["current"]
        self.spec = Spec.model_validate(self.state["spec"])
        self.directory = run / self.current["directory"]
        self.drivers = Drivers(self.spec.drivers)
        self.slots = asyncio.Semaphore(self.spec.limits.concurrency)
        self.stop = asyncio.Event()
        path = self.directory / "probe-budget.json"
        self.budget = load_json(path) if path.exists() else {}
        self.active = 0
        self.tasks = set()

    async def probe(self, role: str, handle: str, action: ProbeAction) -> dict:
        if role not in self.spec.roles and role != "acceptance":
            raise ValueError("Unknown reviewer role")
        if handle not in self.current["targets"]:
            raise ValueError("Unknown target handle")
        target = self.current["targets"][handle]
        if self.spec.schema_version == 2 and role != 'acceptance':
            from deceive.assessment.workflow import plan_path
            path = plan_path(self.run, self.current, role, handle)
            plan = load_json(path) if path.exists() else {}
            if not plan.get('ready') or plan.get('candidate_id') != self.current['candidate_id']:
                raise ValueError('Run assess plan successfully before spending reviewer probe actions')
        if target.get("error"):
            raise ValueError("Target unavailable; controller must diagnose and relaunch it")
        endpoints = target["endpoints"]
        endpoint = next((e for e in endpoints if e["id"] == action.endpoint), None)
        if endpoint is None:
            if action.endpoint or len(endpoints) != 1:
                raise ValueError("Choose an endpoint from this target's service handles")
            endpoint = endpoints[0]
        key = role + "/" + handle
        budget = self.budget.setdefault(key, {"count": 0, "started": time.time()})
        if role != "acceptance":
            if budget["count"] >= self.spec.limits.per_role_target:
                raise ValueError("Reviewer probe budget exhausted")
            if time.time() - budget["started"] > self.spec.limits.reviewer_seconds:
                raise ValueError("Reviewer deadline reached")
        if self.spec.limits.max_elapsed_seconds is not None and (
            time.time() - self.state["started_epoch"] > self.spec.limits.max_elapsed_seconds
        ):
            raise ValueError("Assessment elapsed-time budget exhausted")
        budget["count"] += 1
        write_json(self.directory / "probe-budget.json", self.budget)
        value = {"interaction_id": "interaction-" + uuid.uuid4().hex, "target": handle,
                 "role": role, "candidate_id": self.current["candidate_id"], "timestamp": now(),
                 "action": action, "protocol": endpoint["protocol"]}
        async with self.slots:
            self.active += 1
            try:
                result = await self.drivers.execute(endpoint, action,
                    (role, handle, endpoint["id"], action.session or uuid.uuid4().hex))
                value.update(result)
            except (OSError, ValueError, TimeoutError, ConnectionError) as exc:
                value["error"] = type(exc).__name__ + ": " + str(exc)[:300]
            except Exception as exc:
                # Intentional plugin/protocol boundary: do not expose credential-bearing errors.
                value["error"] = type(exc).__name__
            finally:
                self.active -= 1
        observation = Observation.model_validate(value).model_dump(mode="json")
        path = self.directory / "observations.jsonl"
        with path.open("a") as stream:
            stream.write(json.dumps(observation) + "\n")
        path.chmod(0o600)
        return observation

    async def handle(self, reader, writer) -> None:
        task = asyncio.current_task()
        self.tasks.add(task)
        try:
            line = await asyncio.wait_for(reader.readline(), 10)
            request = json.loads(line)
            if request.get("token") != self.current["broker"]["token"]:
                raise ValueError("Invalid broker token")
            if request.get("operation") == "shutdown":
                pending = [t for t in self.tasks if t is not task]
                for other in pending:
                    other.cancel()
                await asyncio.gather(*pending, return_exceptions=True)
                await self.drivers.close()
                result = {"closed": True}
                self.stop.set()
            elif request.get("operation") == "ping":
                result = {"ready": True, "pid": os.getpid(), 'active':self.active}
            else:
                result = await self.probe(request["role"], request["target"],
                                          ProbeAction.model_validate(request["action"]))
            writer.write((json.dumps({"result": result}) + "\n").encode())
        except (ValueError, KeyError, OSError, TimeoutError) as exc:
            writer.write((json.dumps({"error": str(exc)[:500]}) + "\n").encode())
        finally:
            self.tasks.discard(task)
            try:
                await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()

    async def serve(self) -> None:
        socket = Path(self.current["broker"]["socket"])
        socket.unlink(missing_ok=True)
        server = await asyncio.start_unix_server(self.handle, str(socket), limit=2 * 1024 * 1024)
        socket.chmod(0o600)
        try:
            await self.stop.wait()
        finally:
            server.close()
            await server.wait_closed()
            await self.drivers.close()
            socket.unlink(missing_ok=True)


async def rpc(run: Path, request: dict) -> dict:
    state = load_json(run / "state.json")
    broker = state["current"]["broker"]
    reader, writer = await asyncio.open_unix_connection(broker["socket"], limit=4 * 1024 * 1024)
    try:
        writer.write((json.dumps(request | {"token": broker["token"]}) + "\n").encode())
        await writer.drain()
        deadlines = [e.get("timeout", 35) for t in state["current"]["targets"].values()
                     for e in t.get("endpoints", [])]
        response = json.loads(await asyncio.wait_for(reader.readline(), max([120, *deadlines]) + 15))
        if "error" in response:
            raise ValueError(response["error"])
        return response["result"]
    finally:
        writer.close()
        await writer.wait_closed()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--run", required=True, type=Path)
    args = parser.parse_args()
    asyncio.run(Broker(args.run).serve())
