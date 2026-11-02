"""Install a built wheel through uv in an isolated temporary tool directory."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import urllib.request


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("wheel", type=Path)
    parser.add_argument("--report", type=Path, default=Path("wheel-measurements.json"))
    args = parser.parse_args()
    wheel = args.wheel.resolve()
    with tempfile.TemporaryDirectory(prefix="deceive-wheel-") as directory:
        root = Path(directory)
        env = dict(os.environ, UV_TOOL_DIR=str(root / "tools"), UV_TOOL_BIN_DIR=str(root / "bin"))
        env.pop("PYTHONPATH", None)
        started = time.monotonic()
        subprocess.run(["uv", "tool", "install", "--python", "3.11", str(wheel)],
                       cwd=root, env=env, check=True)
        seconds = time.monotonic() - started
        binary = root / "bin/deceive"
        interpreter = binary.resolve().with_name("python")
        packages = int(subprocess.check_output([str(interpreter), "-c",
            "from importlib.metadata import distributions;print(len(list(distributions())))"],
            cwd=root, env=env, text=True))
        for name in ("demo-http", "linux-ssh", "sudo-2019-14287", "apache-2021-41773"):
            subprocess.run([str(binary), "profile", "validate", name], cwd=root, env=env, check=True)
        subprocess.run([str(binary), "config", "validate", "--deception", "sudo-2019-14287",
                        "--deception", "apache-2021-41773", "--data-dir", str(root / "not-created")],
                       cwd=root, env=env, check=True)
        assert not (root / "not-created").exists()
        acceptance_program = """
import asyncio, json, tempfile
from importlib.resources import files
from pathlib import Path
import yaml
from deceive.evaluate import evaluate
async def run():
    approval = json.loads(files('deceive').joinpath('acceptance/reference-approval.json').read_text())
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        for name in ('sudo-2019-14287', 'apache-2021-41773'):
            suite = files('deceive').joinpath('acceptance', name + '.yaml')
            report = await evaluate(name, suite, root / name)
            assert report['passed_cases'] == report['total_cases'] and report['passed'], report
            assert report['suite_fingerprint'] == approval['suites'][name]
        for version in ('2', '3'):
            suite = yaml.safe_load(files('deceive').joinpath('acceptance/demo-http.yaml').read_text())
            suite['http_version'] = version
            path = root / ('http-' + version + '.json')
            path.write_text(json.dumps(suite))
            report = await evaluate('demo-http', path, root / ('http-' + version))
            assert report['passed_cases'] == report['total_cases'] and report['passed'], report
asyncio.run(run())
"""
        subprocess.run([str(interpreter), "-c", acceptance_program], cwd=root, env=env, check=True)
        composition_program = Path(__file__).with_name("check_composition.py").read_text()
        subprocess.run([str(interpreter), "-c", composition_program], cwd=root, env=env, check=True)
        with (root / "stdout.jsonl").open("w+") as output:
            started = time.monotonic()
            process = subprocess.Popen([str(binary), "serve", "--port", "0", "--host", "127.0.0.1",
                                        "--data-dir", str(root / "data")],
                                       cwd=root, env=env, stdout=output, stderr=subprocess.PIPE, text=True)
            try:
                for _ in range(100):
                    if process.poll() is not None:
                        raise RuntimeError("Installed wheel failed to start: " + process.stderr.read())
                    status_file = root / "data/status.json"
                    if status_file.exists():
                        status = json.loads(status_file.read_text())
                        if status.get("ready"):
                            break
                    time.sleep(0.05)
                else:
                    raise RuntimeError("Installed wheel startup timed out")
                status = json.loads(status_file.read_text())
                startup_seconds = time.monotonic() - started
                port = status["listeners"]["main"][0]["port"]
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                with opener.open(f"http://127.0.0.1:{port}/api/status") as result:
                    assert json.load(result)["status"] == "ok"
                subprocess.run([str(binary), "healthcheck", "--data-dir", str(root / "data")],
                               cwd=root, env=env, check=True)
            finally:
                process.terminate()
                process.wait(timeout=10)
            assert process.returncode == 0
            assert not (root / "data/status.json").exists()
    result = {"wheel": wheel.name, "wheel_bytes": wheel.stat().st_size,
              "installed_packages": packages, "native_install_seconds": round(seconds, 3),
              "native_start_seconds": round(startup_seconds, 3)}
    args.report.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))


if __name__ == "__main__":
    main()
