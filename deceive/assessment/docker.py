from __future__ import annotations

import asyncio
from importlib.resources import files
import io
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import time

from deceive.assessment.models import Spec, Target
from deceive.assessment.drivers import Drivers
from deceive.assessment.workspace import CLIENT_FILES, stage_profile, target_deployment, write_json
from deceive.composition import resolve
from deceive.config import fingerprint, load_profile, read_yaml
from deceive.runtime import Runtime
from deceive.telemetry import Telemetry


class Docker:
    def call(self, *args: str, timeout: float = 60) -> str:
        try:
            result = subprocess.run(["docker", *args], capture_output=True, text=True,
                                    timeout=timeout, check=False)
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            raise RuntimeError(f"Docker {args[0]} unavailable or timed out") from exc
        if result.returncode:
            raise RuntimeError(f"Docker {args[0]} failed: {result.stderr.strip()[-1500:]}")
        return result.stdout.strip()

    def preflight(self) -> None:
        endpoint = self.call("context", "inspect", "--format", "{{.Endpoints.docker.Host}}")
        if not (endpoint.startswith("unix://") or endpoint.startswith("npipe://")):
            raise ValueError("Assessment requires a local Docker daemon")
        version = self.call("info", "--format", "{{.ServerVersion}}")
        if int(version.split(".")[0]) < 28:
            raise ValueError("Docker 28+ is required for loopback port isolation")

    def image(self, spec: Spec, candidate: dict, loop_dir: Path) -> str:
        if not spec.docker.build:
            if not spec.docker.image:
                raise ValueError("docker.image is required when build is false")
            return self.call("image", "inspect", spec.docker.image, "--format", "{{.Id}}")
        tag = "deceive-assess:" + candidate["server_id"][:20]
        result = subprocess.run(["docker", "image", "inspect", tag], capture_output=True, timeout=30)
        if result.returncode:
            output = self.call("build", "-t", tag, str(loop_dir / "source"),
                               timeout=spec.limits.build_seconds)
            (loop_dir / "build.log").write_text(output)
        image = self.call("image", "inspect", tag, "--format", "{{.Id}}")
        expected = {name: digest for name, digest in candidate["files"].items()
                    if name.startswith("deceive/") and not name.startswith((
                        "deceive/assessment/", "deceive/profiles/", "deceive/acceptance/"))
                    and name not in CLIENT_FILES}
        attestation = self.verify_image(image, expected)
        write_json(loop_dir / "image-attestation.json", attestation)
        return image

    def verify_image(self, image: str, expected: dict[str, str]) -> dict:
        if not expected or any(not name.startswith("deceive/") or ".." in Path(name).parts
                               for name in expected):
            raise ValueError("Image attestation requires relative packaged DECEIVE paths")
        program = """import deceive,hashlib,json,sys
from pathlib import Path
root=Path(deceive.__file__).parent
observed={}
for name in json.loads(sys.argv[1]):
    path=root/Path(name).relative_to('deceive')
    observed[name]=hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None
print(json.dumps(observed))
"""
        observed = json.loads(self.call("run", "--rm", "--network", "none", "--read-only",
            "--entrypoint", "python", image, "-c", program, json.dumps(list(expected))))
        mismatches = [name for name, digest in expected.items() if observed.get(name) != digest]
        if mismatches:
            raise RuntimeError("Installed image source differs from the candidate; rebuild the project wheel: "
                               + ", ".join(mismatches[:10]))
        return {"schema_version": 1, "image": image, "matched": True, "checked": len(expected),
                "expected": expected, "observed": observed}

    def owned(self, container: str, run_id: str) -> None:
        label = self.call("inspect", "--format", '{{ index .Config.Labels "deceive.assessment" }}', container)
        if label != run_id:
            raise ValueError("Refusing to change a container not owned by this assessment")

    def stop(self, entry: dict, run_id: str) -> None:
        self.owned(entry["container"], run_id)
        self.call("stop", "--time", "10", entry["container"], timeout=20)

    def remove(self, entry: dict, run_id: str, volumes: bool = False) -> None:
        self.owned(entry["container"], run_id)
        self.call("rm", "-f", entry["container"])
        if volumes:
            label = self.call("volume", "inspect", entry["volume"], "--format",
                              '{{ index .Labels "deceive.assessment" }}')
            if label != run_id:
                raise ValueError("Refusing to remove an unowned volume")
            self.call("volume", "rm", entry["volume"])

    def remove_network(self, name: str, run_id: str) -> None:
        label = self.call("network", "inspect", name, "--format",
                          '{{ index .Labels "deceive.assessment" }}')
        if label != run_id:
            raise ValueError("Refusing to remove an unowned network")
        self.call("network", "rm", name)


def reserve(transport: str) -> tuple[socket.socket, int]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if transport == "udp" else socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    return sock, sock.getsockname()[1]


def aws_credentials(providers: dict, directory: Path | None) -> tuple[list[tuple[str, str]], dict[str, str]]:
    bedrock = [provider for provider in providers.values() if provider.kind == "bedrock"]
    if not bedrock:
        return [], {}
    if directory is None:
        if any(provider.aws_profile for provider in bedrock):
            raise ValueError("A named AWS profile requires docker.aws_dir for assessment")
        return [], {}
    if not directory.is_dir() or "," in str(directory):
        raise ValueError("AWS credential directory is missing or has an unsupported path")
    return [(str(directory), "/material/aws")], {
        "AWS_SHARED_CREDENTIALS_FILE": "/material/aws/credentials",
        "AWS_CONFIG_FILE": "/material/aws/config",
    }


async def deploy(docker: Docker, run: Path, state: dict, spec: Spec, target: Target,
                 handle: str, image: str, loop_dir: Path) -> dict:
    config = target_deployment(spec, target)
    plan = resolve(config)
    if len(plan.listeners) == 1:
        listener = plan.listeners[0]
        if target.protocol:
            listener.protocol = target.protocol
        if target.versions:
            listener.versions = target.versions
    elif target.protocol or target.versions:
        raise ValueError("Transport overrides require a single-listener target")
    # Assessment service names must not follow content-derived auto listener
    # names: changing only a mounted profile must retain its keys and bindings.
    listeners = sorted(plan.listeners, key=lambda l: (
        l.protocol, l.port, tuple(sorted(p.id for p in plan.members[l.name]))))
    for index, listener in enumerate(listeners):
        listener.name = f"assessment-service-{index + 1}"
    config.listeners, config.deceptions = listeners, []
    checker = Runtime(config, telemetry=Telemetry("assessment", stream=io.StringIO()))
    await checker.close()
    plan = checker.plan
    private = run / "resources" / handle
    stage = private / "stage"
    stage.mkdir(parents=True, exist_ok=True)
    stage.chmod(0o755)
    old = state["containers"].get(handle)
    if old:
        docker.stop(old, state["run_id"])
    for path in stage.iterdir():
        if path.is_file():
            path.unlink()
    endpoints, secrets, envs, reservations = [], [], set(), []
    profiles = []
    deployment = config.model_dump(mode="json")
    deployment.update(data_dir="/data", log_file=None, deceptions=[],
                      sensor_name=f'{state["run_id"]}-loop-{state["current"]["number"]}-attempt-{state["current"]["attempt"]}-{handle}')
    for index, listener in enumerate(plan.listeners):
        row = listener.model_dump(mode="json")
        row["host"] = "0.0.0.0"
        for key in ("host_key", "cert_file", "key_file"):
            if row[key]:
                name = f"material-{index}-{key}"
                secrets.append((row[key], "/material/" + name))
                row[key] = "/material/" + name
        references = listener.profiles or [listener.profile]
        staged = [stage_profile(ref, stage) for ref in references]
        if listener.profile:
            row["profile"], row["profiles"] = staged[0], []
        else:
            row["profile"], row["profiles"] = None, staged
        if target.calibration:
            if listener.protocol not in {"http", "https"}:
                raise ValueError("Server-version calibration requires an HTTP target")
            profile_path = stage / Path(staged[0]).name
            raw = read_yaml(profile_path)
            raw.setdefault("behaviors", []).insert(0, {"id": "calibration-index",
                "match": {"path": "/"}, "reply": {"body": "Archive service ready\n",
                    "headers": [["server", "Apache/9.9.9"]]}})
            profile_path.write_text(json.dumps(raw))
            profile_path.chmod(0o644)
        if row["port"] == 0:
            row["port"] = 8022 if listener.protocol == "ssh" else 8443 if listener.protocol == "https" else 8080
        if listener.protocol == "https" and "3" in listener.versions:
            row["quic_port"] = row["quic_port"] or row["port"]
        drivers = Drivers(spec.drivers)
        try:
            if listener.protocol not in drivers.registry:
                raise ValueError(f"Missing assessment driver: {listener.protocol}")
            bindings = drivers.registry[listener.protocol].bindings(row)
        finally:
            await drivers.close()
        endpoint = {"id": f"service-{index + 1}", "listener": listener.name,
                    "protocol": listener.protocol, "versions": listener.versions, "ports": {},
                    "username": "guest", "password": "", "timeout": config.limits.request_seconds +
                    (config.limits.llm_seconds if listener.analyze else 0) + 5}
        for transport, internal in bindings:
            if transport not in {"tcp", "udp"} or not 1 <= internal <= 65535:
                raise ValueError("Assessment drivers must declare bounded TCP/UDP bindings")
            endpoint["ports"][transport] = {"internal": internal}
        if listener.accounts:
            user, password = next(iter(listener.accounts.items()))
            endpoint.update(username=user, password="" if password == "*" else password)
        endpoints.append(endpoint)
        deployment["listeners"][index] = row
        for member in plan.members[listener.name]:
            member_index = next(i for i, ref in enumerate(references) if load_profile(ref).id == member.id)
            profiles.append({"id": member.id, "version": member.version,
                             "fingerprint": fingerprint(member), "reference": references[member_index],
                             "staged_reference": staged[member_index],
                             "description": member.description, "references": member.references,
                             "limitations": member.limitations, "listener": listener.name})
    for name, provider in config.providers.items():
        raw = deployment["providers"][name]
        if provider.api_key_file:
            secrets.append((str(provider.api_key_file), "/material/provider-" + name))
            raw["api_key_file"] = "/material/provider-" + name
        if provider.api_key_env:
            envs.add(provider.api_key_env)
        else:
            envs.update({"openai": ["OPENAI_API_KEY"], "azure": ["AZURE_OPENAI_API_KEY"],
                         "gemini": ["GOOGLE_API_KEY", "GEMINI_API_KEY"],
                         "bedrock": ["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
                                     "AWS_DEFAULT_REGION", "AWS_REGION", "AWS_PROFILE", "AWS_DEFAULT_PROFILE"],
                         }.get(provider.kind, []))
    aws_mounts, aws_env = aws_credentials(config.providers, spec.docker.aws_dir)
    secrets.extend(aws_mounts)
    if config.providers and not spec.docker.provider_network:
        raise ValueError("Model-backed targets require explicit docker.provider_network: true")
    layout = fingerprint({"image": image, "endpoints": endpoints, "secrets": secrets,
                          "envs": sorted(envs), "aws_env": aws_env,
                          "provider_network": spec.docker.provider_network})
    name = f'{state["run_id"]}-{handle}'
    volume, network = name + "-data", state["run_id"] + "-net"
    if not state.get("network"):
        # A dedicated ordinary bridge is needed for host loopback publishing on
        # Docker Desktop. Provider permission is separate from network isolation.
        options = []
        docker.call("network", "create", "--label", "deceive.assessment=" + state["run_id"],
                    *options, network)
        state["network"] = network
        write_json(run / "state.json", state)
    reuse = bool(old and old["layout"] == layout and not config.providers)
    if old and not reuse:
        docker.remove(old, state["run_id"])
    if not old:
        docker.call("volume", "create", "--label", "deceive.assessment=" + state["run_id"], volume)
        owner = docker.call("volume", "inspect", volume, "--format", '{{ index .Labels "deceive.assessment" }}')
        if owner != state["run_id"]:
            raise ValueError("Refusing to reuse another owner's data volume")
    try:
        if reuse:
            endpoints = old["endpoints"]
        else:
            for endpoint in endpoints:
                for transport, mapping in endpoint["ports"].items():
                    sock, port = reserve(transport)
                    reservations.append(sock)
                    mapping["host"] = port
        for row, endpoint in zip(deployment["listeners"], endpoints):
            if "udp" in endpoint["ports"]:
                row["advertised_port"] = endpoint["ports"]["udp"]["host"]
        (stage / "deployment.yaml").write_text(json.dumps(deployment, indent=2))
        (stage / "deployment.yaml").chmod(0o644)
        for module in ("evaluate", "clients"):
            shutil.copy2(loop_dir / "source/deceive" / (module + ".py"), stage / ("current_" + module + ".py"))
        archive = loop_dir / "targets" / handle
        archive.mkdir(parents=True, exist_ok=True)
        shutil.copytree(stage, archive / "stage", dirs_exist_ok=True)
        if not reuse:
            options = ["create", "--name", name, "--label", "deceive.assessment=" + state["run_id"],
                       "--network", network, "--memory", "512m", "--pids-limit", "128",
                       "--mount", f"type=bind,src={stage},dst=/stage,readonly",
                       "--mount", f"source={volume},target=/data"]
            for endpoint in endpoints:
                for transport, mapping in endpoint["ports"].items():
                    options += ["-p", f'127.0.0.1:{mapping["host"]}:{mapping["internal"]}/{transport}']
            for source, destination in secrets:
                options += ["--mount", f"type=bind,src={source},dst={destination},readonly"]
            for variable in sorted(envs):
                if os.environ.get(variable):
                    options += ["-e", variable]
            for variable, value in aws_env.items():
                options += ["-e", variable + "=" + value]
            docker.call(*options, image, "serve", "--config", "/stage/deployment.yaml")
        for sock in reservations:
            sock.close()
        entry = {"container": name, "volume": volume, "layout": layout, "image": image,
                 "endpoints": endpoints, "profiles": profiles, "calibration": bool(target.calibration),
                 "target_name": target.name, "reused": reuse,
                 "sensor": deployment["sensor_name"], "stage": str(stage),
                 "allowed_profile_ids": sorted({p.id for owners in plan.owners.values()
                                                 for p in owners.values()})}
        state["containers"][handle] = entry
        write_json(run / "state.json", state)
        docker.call("start", name)
        deadline = time.monotonic() + spec.limits.startup_seconds
        while time.monotonic() < deadline:
            result = subprocess.run(["docker", "exec", name, "deceive", "healthcheck"],
                                    capture_output=True, timeout=5)
            if result.returncode == 0:
                break
            if docker.call("inspect", "--format", "{{.State.Running}}", name) == "false":
                raise RuntimeError("Assessment target exited before readiness")
            await asyncio.sleep(0.15)
        else:
            raise RuntimeError("Assessment target readiness timed out")
        ports = json.loads(docker.call("inspect", "--format", "{{json .NetworkSettings.Ports}}", name))
        for endpoint in endpoints:
            for transport, mapping in endpoint["ports"].items():
                published = ports[f'{mapping["internal"]}/{transport}']
                if published != [{"HostIp": "127.0.0.1", "HostPort": str(mapping["host"])}]:
                    raise ValueError("Unexpected Docker port exposure")
        write_json(archive / "private.json", entry)
        return entry
    finally:
        for sock in reservations:
            sock.close()
