"""Exercise an already-built image. No registry publishing or live model calls."""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import time
import uuid

import asyncssh
import httpx

from deceive.clients import h3_connect
from deceive.assessment.docker import Docker
from deceive.assessment.workspace import source_files, packaged_assets


def docker(*args: str) -> str:
    return subprocess.check_output(["docker", *args], text=True).strip()


async def verify(image: str) -> dict:
    root = Path(__file__).resolve().parents[1]
    expected = {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in source_files(root) if p.relative_to(root).parts[0] == "deceive"}
    expected.update(packaged_assets({str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
                                    for p in source_files(root)}))
    attestation = Docker().verify_image(image, expected)
    token = "deceive-smoke-" + uuid.uuid4().hex[:12]
    volume = token + "-data"
    docker("volume", "create", volume)
    started = time.monotonic()
    architecture = docker("image", "inspect", image, "--format", "{{.Architecture}}")
    host_architecture = docker("info", "--format", "{{.Architecture}}")
    host_architecture = {"aarch64": "arm64", "x86_64": "amd64"}.get(host_architecture, host_architecture)
    measurements = {"image": image,
                    "installed_source_files_checked": attestation["checked"],
                    "platform": "linux/" + architecture,
                    "emulated": architecture != host_architecture}
    try:
        with tempfile.TemporaryDirectory() as directory:
            profile = Path(directory) / "ssh.yaml"
            profile.write_text("id: smoke-ssh\nprotocol: ssh\nbehaviors:\n  - id: identity\n    kind: identity\n")
            for mode in ("http", "ssh", "ssh", "https", "https"):
                name = token + "-" + uuid.uuid4().hex[:6]
                options = ["run", "--platform", "linux/" + architecture, "-d", "--name", name,
                           "--mount", f"source={volume},target=/data"]
                if mode == "http":
                    options += ["-p", "127.0.0.1::8080/tcp", image]
                elif mode == "ssh":
                    options += ["-p", "127.0.0.1::8022/tcp", "--mount",
                                f"type=bind,source={profile},target=/config/ssh.yaml,readonly", image,
                                "serve", "--profile", "/config/ssh.yaml"]
                else:
                    options += ["-p", "127.0.0.1::8443/tcp", "-p", "127.0.0.1::8443/udp", image,
                                "serve", "--profile", "demo-http", "--https",
                                "--http-versions", "1.1", "2", "3"]
                docker(*options)
                try:
                    for _ in range(100):
                        probe = subprocess.run(["docker", "exec", name, "deceive", "healthcheck"],
                                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                        if probe.returncode == 0:
                            break
                        await asyncio.sleep(0.1)
                    else:
                        raise AssertionError("Container did not become ready")
                    if mode == "http":
                        measurements["cold_start_seconds"] = round(time.monotonic() - started, 3)
                    assert docker("exec", name, "id", "-u") == "10001"
                    inspect = json.loads(docker("inspect", name))[0]
                    ports = inspect["NetworkSettings"]["Ports"]
                    if mode == "ssh":
                        port = int(ports["8022/tcp"][0]["HostPort"])
                        async with asyncssh.connect("127.0.0.1", port=port, username="guest", known_hosts=None) as client:
                            assert (await client.run("hostname")).stdout == "build-node-03\n"
                        key = docker("exec", name, "python", "-c",
                            "import hashlib;print(hashlib.sha256(open('/data/keys/main-ssh-key','rb').read()).hexdigest())")
                        assert measurements.setdefault("ssh_key_sha256", key) == key
                    else:
                        internal = "8080/tcp" if mode == "http" else "8443/tcp"
                        port = int(ports[internal][0]["HostPort"])
                        async with httpx.AsyncClient(verify=False, http2=mode == "https", trust_env=False) as client:
                            result = await client.get(f"{mode}://127.0.0.1:{port}/download")
                            assert result.content == b"\x00\xff\x80A"
                            assert result.http_version == ("HTTP/2" if mode == "https" else "HTTP/1.1")
                        if mode == "https":
                            udp = int(ports["8443/udp"][0]["HostPort"])
                            async with h3_connect(udp) as client:
                                result = await client.request("GET", "/api/status")
                                assert result.version == "3" and result.status == 200
                                head = await client.request("HEAD", "/download")
                                assert head.status == 200 and head.body == b""
                                assert (b"content-length", b"4") in head.headers
                            key = docker("exec", name, "python", "-c",
                                "import hashlib;print(hashlib.sha256(open('/data/certificates/main.key','rb').read()).hexdigest())")
                            assert measurements.setdefault("tls_key_sha256", key) == key
                    measurements["installed_packages"] = int(docker("exec", name, "python", "-c",
                        "from importlib.metadata import distributions;print(len(list(distributions())))"))
                    docker("exec", name, "python", "-c",
                           "import openai,ollama,boto3;from google import genai;"
                           "import importlib.util;assert importlib.util.find_spec('torch') is None;"
                           "assert importlib.util.find_spec('langchain') is None")
                    await asyncio.to_thread(docker, "stop", "--time", "10", name)
                    assert docker("inspect", "--format", "{{.State.ExitCode}}", name) == "0"
                    records = [json.loads(line) for line in docker("logs", name).splitlines()]
                    assert any(r["message"] == "User input" for r in records)
                    assert any(r["message"] == "Session summary" for r in records)
                finally:
                    subprocess.run(["docker", "rm", "-f", name], stdout=subprocess.DEVNULL, check=False)
    finally:
        docker("volume", "rm", volume)
    # Exercise the shipped CVE suites inside the installed image with all
    # external networking disabled. Only the container's loopback is used.
    program = """
import asyncio, json, tempfile
from importlib.resources import files
from pathlib import Path
from deceive.evaluate import evaluate
from deceive.vulnerability_catalog import approval_for, bundled_vulnerabilities
async def run():
    reports = []
    with tempfile.TemporaryDirectory() as directory:
        for name in bundled_vulnerabilities():
            suite = files('deceive').joinpath('acceptance', name + '.yaml')
            report = await evaluate(name, suite, Path(directory) / name)
            assert report['passed'] and report['passed_cases'] == report['total_cases'], report
            assert report['suite_fingerprint'] == approval_for(name)['suites'][name]
            reports.append({'profile': name, 'cases': report['total_cases'],
                            'suite_fingerprint': report['suite_fingerprint']})
    print(json.dumps(reports))
asyncio.run(run())
"""
    measurements["reference_acceptance"] = json.loads(docker(
        "run", "--rm", "--platform", "linux/" + architecture, "--network", "none",
        "--entrypoint", "python", image, "-c", program))
    composition_program = Path(__file__).with_name("check_composition.py").read_text()
    measurements["composition"] = json.loads(docker(
        "run", "--rm", "--platform", "linux/" + architecture, "--network", "none",
        "--entrypoint", "python", image, "-c", composition_program))
    ssh_program = Path(__file__).with_name("check_ssh_fidelity.py").read_text()
    measurements["ssh_fidelity"] = json.loads(docker(
        "run", "--rm", "--platform", "linux/" + architecture, "--network", "none",
        "--entrypoint", "python", image, "-c", ssh_program))
    skills_program = Path(__file__).with_name("check_installed_skills.py").read_text()
    measurements["skills"] = json.loads(docker(
        "run", "--rm", "--platform", "linux/" + architecture, "--network", "none",
        "--entrypoint", "python", image, "-c", skills_program))
    # Containerd may report only compressed content before a foreign-platform
    # image's first run. Measure after unpacking for comparable stored sizes.
    measurements["image_bytes"] = int(docker("image", "inspect", image, "--format", "{{.Size}}"))
    return measurements


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("image")
    parser.add_argument("--report", type=Path, default=Path("container-measurements.json"))
    args = parser.parse_args()
    result = asyncio.run(verify(args.image))
    args.report.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))


if __name__ == "__main__":
    main()
