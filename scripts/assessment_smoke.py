"""Model-free Docker integration check for the assessment controller and protocol drivers."""
from __future__ import annotations

import argparse
import asyncio
import base64
from importlib.resources import files
import json
from pathlib import Path
import tempfile

from deceive.assessment import engine
from deceive.assessment.models import Review
from deceive.assessment.workspace import load_json, prepare
from deceive.config import load_profile


async def verify(image: str, root: Path) -> dict:
    with tempfile.TemporaryDirectory(prefix="deceive-assessment-smoke-") as directory:
        base = Path(directory)
        profile = load_profile("demo-http").model_dump(mode="json")
        profile["id"] = "docker-smoke"
        profile["behaviors"].insert(0, {"id": "update", "match": {"path": "/smoke"}, "reply": {"body": "one"}})
        custom = base / "profile.yaml"
        custom.write_text(json.dumps(profile))
        spec = base / "spec.yaml"
        spec.write_text(json.dumps({"policy": {"mode": "fixed", "max_loops": 2, "confirmations": 1}, "roles": ["protocol"],
            "docker": {"build": False, "image": image}, "targets": [
                {"name": "web", "profiles": [str(custom)], "protocol": "https", "versions": ["2", "3"],
                 "suite": str(files("deceive").joinpath("acceptance/demo-http.yaml"))},
                {"name": "sudo", "profiles": ["sudo-2019-14287"]},
                {"name": "group", "profiles": ["sudo-2019-14287", "apache-2021-41773"]}]}))
        run = base / "run"
        prepare(spec, run, root)
        containers = None
        try:
            for number in (1, 2):
                if number == 2:
                    profile["behaviors"][0]["reply"]["body"] = "two"
                    custom.write_text(json.dumps(profile))
                public = await engine.begin_loop(run)
                state = load_json(run / "state.json")
                names = {h: e["container"] for h, e in state["containers"].items()}
                if containers is not None:
                    assert names == containers
                    assert all(e["reused"] for e in state["containers"].values())
                containers = names
                for handle, entry in state["current"]["targets"].items():
                    assert not entry.get("error"), entry
                    assert state["current"]["correctness"][handle]["status"] == "passed", state["current"]["correctness"]
                    for endpoint in entry["endpoints"]:
                        versions = endpoint["versions"] if endpoint["protocol"] != "ssh" else ["ssh"]
                        for version in versions:
                            action = {"endpoint": endpoint["id"], "operation": "exec" if version == "ssh" else "request",
                                      "parameters": {"command": "hostname"} if version == "ssh" else {
                                          "path": "/smoke" if handle == "target-01" else "/", "version": version}}
                            observation = await engine.rpc(run, {"role": "protocol", "target": handle, "action": action})
                            assert not observation.get("error"), observation
                            assert observation["version"] == version
                            if handle == "target-01":
                                assert base64.b64decode(observation["body_base64"]) == (b"one" if number == 1 else b"two")
                    engine.record_review(run, Review(candidate_id=public["candidate_id"], role="protocol", target=handle,
                        synthetic_confidence=10, verdict_confidence=100,
                        summary="Deterministic integration fixture; not a live realism assessment"))
                result = await engine.end_loop(run)
                assert result["qualified"], result
            final = await engine.finish(run)
            assert final["qualified"]
            assert Path(final["dashboard"]).is_file()
            return {"passed": True, "loops": 2, "profile_update_reused_containers": True,
                    "protocols": ["ssh", "1.1", "2", "3"], "live_reviewers": False}
        finally:
            await engine.finish(run, remove=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("image")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    print(json.dumps(asyncio.run(verify(args.image, args.root.resolve()))))
