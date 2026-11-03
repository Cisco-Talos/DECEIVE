"""Exercise the public managed-deployment CLI against a locally installed image."""
from __future__ import annotations

import argparse
import asyncio
import base64
from importlib.resources import files
import json
from pathlib import Path
import subprocess
import sys
import tempfile

from deceive.assessment.drivers import Drivers
from deceive.assessment.models import ProbeAction
from deceive.config import load_profile
from deceive.evaluate import evaluate_external


async def verify(image: str) -> dict:
    with tempfile.TemporaryDirectory(prefix="deceive-managed-") as directory:
        root = Path(directory)
        state = root / "state"
        def command(*args: str) -> dict:
            completed = subprocess.run([sys.executable, "-m", "deceive", "deployment", *args,
                "--state-dir", str(state), "--json"], capture_output=True, text=True, timeout=90)
            result = json.loads(completed.stdout)
            assert completed.returncode == 0 and result["ok"], result
            return result["data"]

        base = load_profile("demo-http").model_dump(mode="json")
        base.update(id="managed-base", prompt_file="prompt.txt")
        (root / "base.json").write_text(json.dumps(base))
        (root / "prompt.txt").write_text("The archive contains only virtual data.")
        binary = b"\x00\xffmanaged-asset\n"
        (root / "asset.bin").write_bytes(binary)
        for name, path, reply in (("download", "/download", {"body_file": "asset.bin"}),
                                  ("metrics", "/metrics", {"body": "ready\n"})):
            (root / f"{name}.json").write_text(json.dumps({"id": "managed-" + name,
                "requirements": {"protocol": "https", "base_profile": "base.json", "base_version": "1",
                    "http_versions": ["1.1", "2", "3"]},
                "behaviors": [{"id": name, "match": {"path": path}, "reply": reply}]}))
        config = root / "deployment.json"
        config.write_text(json.dumps({"listeners": [
            {"name": "web", "protocol": "https", "profile": str(root / "download.json"),
             "port": 0, "quic_port": 0, "versions": ["1.1", "2", "3"]},
            {"name": "ssh", "protocol": "ssh", "profile": "sudo-2019-14287", "port": 0},
            {"name": "apache", "protocol": "http", "profile": "apache-2021-41773", "port": 0}]}))
        drivers = Drivers()
        result = {}
        try:
            first = command("start", "smoke", "--config", str(config), "--deception",
                            str(root / "metrics.json"), "--image", image)
            assert first["ready"] and len(first["listeners"]) == 3
            assert {p["id"] for p in first["profiles"]} == {
                "managed-download", "managed-metrics", "sudo-2019-14287", "apache-2021-41773"}
            assert len(command("list")["deployments"]) == 1
            endpoints = {row["name"]: {"id": row["name"], "protocol": row["protocol"],
                "versions": row["versions"], "username": "guest", "password": "",
                "ports": {b["transport"]: {"host": b["host_port"]} for b in row["bindings"]}}
                for row in first["listeners"]}

            async def request(name: str, value: dict) -> dict:
                action = ProbeAction.model_validate(value)
                return await drivers.execute(endpoints[name], action, (name, value.get("session")))

            for version in ("1.1", "2", "3"):
                session = "web-" + version.replace(".", "-")
                await request("web", {"operation": "request", "session": session,
                    "parameters": {"version": version, "path": "/api/status"}})
                results = await asyncio.gather(*(request("web", {"operation": "request", "parameters": {
                    "version": version, "path": path}, "session": session}) for path in ("/download", "/metrics")))
                assert all(row["version"] == version for row in results), results
                assert base64.b64decode(results[0]["body_base64"]) == binary, (version, results)
                assert base64.b64decode(results[1]["body_base64"]) == b"ready\n", (version, results)
                if version == "3":
                    headers = [(base64.b64decode(k).lower(), base64.b64decode(v)) for k, v in results[0]["headers"]]
                    udp = endpoints["web"]["ports"]["udp"]["host"]
                    assert any(k == b"alt-svc" and str(udp).encode() in v for k, v in headers)
            acceptance = []
            for name, profile, protocol in (("ssh", "sudo-2019-14287", "ssh"),
                                             ("apache", "apache-2021-41773", "http")):
                async def execute(action):
                    return await request(name, action)
                report = await evaluate_external(Path(str(files("deceive").joinpath("acceptance", profile + ".yaml"))),
                                                 protocol, "1.1", execute)
                assert report["external_passed"], report
                acceptance.append({"profile": profile, "base_cases_passed": True,
                                   "variant_cases": sum(case.get("backend") == "requires_variant" for case in report["cases"])})
            await drivers.close()
            assert command("stop", "smoke")["state"] == "exited"
            restarted = command("start", "smoke")
            assert restarted["ready"] and restarted["container"] == first["container"]
            assert restarted["volume"] == first["volume"] and restarted["listeners"] == first["listeners"]
            assert command("status", "smoke")["ready"]
            result = {"passed": True, "protocols": ["ssh", "1.1", "2", "3"],
                      "composition": True, "relative_assets": True, "binary_content": True,
                      "restart_reused_container_and_volume": True, "acceptance": acceptance}
        finally:
            await drivers.close()
            if (state / "smoke/record.json").exists():
                command("stop", "smoke")
                command("remove", "smoke", "--remove-data")
                assert not command("list")["deployments"]
        return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("image")
    parser.add_argument("--report", type=Path, default=Path("managed-measurements.json"))
    args = parser.parse_args()
    result = asyncio.run(verify(args.image))
    args.report.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))


if __name__ == "__main__":
    main()
