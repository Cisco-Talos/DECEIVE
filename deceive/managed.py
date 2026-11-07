"""Operator-owned Docker deployments; independent of assessment resources."""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import time
import uuid

from deceive.config import fingerprint, load_profile
from deceive.composition import Plan
from deceive.models import Deployment
from deceive.credentials import literal_name, selected_environment
from deceive.runtime import Runtime
from deceive.telemetry import Telemetry


def write_json(path: Path, value: dict, *, mode: int = 0o600) -> None:
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n")
    temporary.chmod(mode)
    temporary.replace(path)


def snapshot_profile(reference: str, destination: Path, seen: tuple[str, ...] = (), *, profile=None) -> str:
    profile = profile if profile is not None else load_profile(reference)
    if reference in seen or len(seen) >= 10:
        raise ValueError("Cyclic/deep profile dependencies")
    # Assets are already embedded by load_profile; preserve omitted inherited defaults.
    raw = profile.model_dump(mode="json", exclude_unset=True)
    if profile.requirements and profile.requirements.base_profile:
        raw["requirements"]["base_profile"] = snapshot_profile(
            profile.requirements.base_profile, destination, seen + (reference,), profile=profile._bound_base)
    name = "profile-" + fingerprint(raw)[:20] + ".json"
    write_json(destination / name, raw, mode=0o644)
    return "/config/" + name


class DockerCLI:
    def command(self, *args: str, timeout: float = 30,
                env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
        try:
            return subprocess.run(["docker", *args], capture_output=True, text=True,
                                  timeout=timeout, check=False, env=env)
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            raise RuntimeError("Docker is unavailable or timed out; check the local daemon") from exc

    def call(self, *args: str, timeout: float = 30, env: dict[str, str] | None = None) -> str:
        result = self.command(*args, timeout=timeout, **({'env': env} if env is not None else {}))
        if result.returncode:
            # Do not expose environment values or configuration through daemon errors.
            raise RuntimeError(f"Docker {args[0]} failed; check the image, daemon, mounts and port availability")
        return result.stdout.strip()

    def inspect(self, kind: str, name: str) -> dict | None:
        result = self.command(kind, "inspect", "--format", "{{json .}}", name)
        if result.returncode:
            error = result.stderr.lower()
            missing = (f"no such {kind}" in error or "no such object" in error
                       or f"network {name.lower()} not found" in error)
            if name.lower() in error and missing:
                return None
            raise RuntimeError("Docker inspection failed; check the local daemon and access")
        return json.loads(result.stdout)

    def preflight(self) -> None:
        endpoint = self.call("context", "inspect", "--format", "{{.Endpoints.docker.Host}}")
        if not endpoint.startswith(("unix://", "npipe://")):
            raise ValueError("Managed deployments require a local Docker daemon")
        version = self.call("info", "--format", "{{.ServerVersion}}")
        if int(version.split(".")[0]) < 28:
            raise ValueError("Docker 28+ is required for reliable loopback publishing")


class DeploymentManager:
    def __init__(self, root: Path, docker: DockerCLI | None = None):
        self.root = root.resolve()
        self.docker = docker or DockerCLI()

    def directory(self, name: str) -> Path:
        if not re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", name):
            raise ValueError("Deployment names must start with a lowercase letter and use letters, digits, _ or - (64 maximum)")
        return self.root / name

    def owner(self, *, create: bool = False) -> str | None:
        path = self.root / "owner.json"
        if create:
            self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
            with (self.root / "owner.lock").open("a") as stream:
                fcntl.flock(stream, fcntl.LOCK_EX)
                if not path.exists():
                    write_json(path, {"schema_version": 1, "id": uuid.uuid4().hex})
        if not path.exists():
            return None
        value = json.loads(path.read_text())
        if value.get("schema_version") != 1 or not re.fullmatch(r"[a-f0-9]{32}", value.get("id", "")):
            raise ValueError("Invalid managed-deployment owner record")
        return value["id"]

    @contextmanager
    def locked(self, name: str):
        directory = self.directory(name)
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        with (directory / "operation.lock").open("a") as stream:
            try:
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise ValueError("Another command is changing this deployment") from exc
            yield directory

    def record(self, name: str) -> dict:
        path = self.directory(name) / "record.json"
        if not path.is_file():
            raise ValueError(f"Unknown managed deployment: {name}")
        record = json.loads(path.read_text())
        if (record.get("schema_version") != 1 or record.get("owner") != self.owner()
                or record.get("name") != name):
            raise ValueError("Invalid managed-deployment record")
        return record

    def owned(self, kind: str, resource: str, record: dict) -> dict | None:
        info = self.docker.inspect(kind, resource)
        if info is not None:
            labels = info.get("Config", {}).get("Labels", {}) if kind == "container" else info.get("Labels", {})
            if (labels.get("deceive.managed") != record["owner"]
                    or labels.get("deceive.deployment") != record["name"]):
                raise ValueError("Refusing to control a resource owned by another deployment")
        return info

    def status(self, name: str) -> dict:
        record = self.record(name)
        info = self.owned("container", record["container"], record) if record.get("container") else None
        state = info["State"]["Status"] if info else "missing"
        ready = bool(info and info["State"].get("Running") and self.docker.command(
            "exec", record["container"], "deceive", "healthcheck").returncode == 0)
        return {key: record[key] for key in ("name", "image", "volume", "network", "created_at",
                                            "config_fingerprint", "profiles", "listeners", "notes")} | {
            "state": state, "ready": ready, "container": record.get("container"),
            "exit_code": info["State"].get("ExitCode") if info else None,
            "state_dir": str(self.directory(name))}

    def list(self) -> list[dict]:
        if not self.root.exists():
            return []
        return [self.status(path.parent.name) for path in sorted(self.root.glob("*/record.json"))]

    @staticmethod
    def reserve(host: str, transport: str, preferred: int = 0) -> tuple[socket.socket, int]:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if transport == "udp" else socket.SOCK_STREAM)
        try:
            sock.bind((host, preferred))
        except OSError:
            sock.close()
            raise
        return sock, sock.getsockname()[1]

    async def start(self, name: str, config: Deployment | None, *, image: str | None = None,
                    publish_host: str = "127.0.0.1", publish: tuple[str, ...] | list[str] = (),
                    env_names: tuple[str, ...] | list[str] = (), aws_dir: Path | None = None,
                    timeout: float = 30, skip_preflight: bool = False) -> dict:
        if not 0 < timeout <= 600:
            raise ValueError("Startup timeout must be greater than 0 and at most 600 seconds")
        if ipaddress.ip_address(publish_host).version != 4:
            raise ValueError("Managed publishing currently requires an IPv4 address")
        self.directory(name)
        if config is None and not (self.directory(name) / "record.json").exists():
            raise ValueError("A new deployment requires a profile or deployment configuration")
        options = {"publish_host": publish_host, "publish": sorted(publish),
                   "env_names": sorted(env_names), "aws_dir": str(aws_dir.resolve()) if aws_dir else None,
                   'skip_preflight': skip_preflight}
        runtime = None
        if config is not None:
            runtime = Runtime(config, telemetry=Telemetry(config.sensor_name, stream=io.StringIO()))
            try:
                plan = runtime.plan
            finally:
                await runtime.close()
        self.docker.preflight()
        owner = self.owner(create=True)
        with self.locked(name) as directory:
            if (directory / "record.json").exists():
                record = self.record(name)
                if config is None and skip_preflight and not record['options'].get('skip_preflight'):
                    raise ValueError('Restart retains its preflight policy; replace the stopped container to change it')
                if config is not None and record.get('plan_fingerprint') and record['plan_fingerprint'] != fingerprint(
                    {key: fingerprint(value) for key, value in plan.profiles.items()}
                ):
                    raise ValueError('Resolved profile/organization content changed; replace the stopped container to apply it (data is retained)')
                if config is not None and record["config_fingerprint"] != fingerprint(config.model_dump(mode="json")):
                    raise ValueError("Deployment configuration changed; stop and remove its container before starting a replacement (data is retained)")
                if config is not None and record["options"] != options:
                    raise ValueError("Deployment options changed; remove the stopped container before replacing it")
                if image and self.docker.call("image", "inspect", image, "--format", "{{.Id}}") != record["image"]:
                    raise ValueError("Deployment image changed; stop and remove its container before replacing it")
                if config is None and (publish or env_names or aws_dir or publish_host != "127.0.0.1"):
                    raise ValueError("Restart uses retained settings; remove the stopped container to change deployment options")
                info = self.owned("container", record["container"], record) if record.get("container") else None
                if info is None:
                    raise ValueError("Managed container is missing; remove its record before starting a replacement")
                if not info["State"].get("Running"):
                    if 'skip_preflight' not in record['options']:
                        raise ValueError('Retained container predates startup preflight; replace it to adopt the current startup policy (data is retained)')
                    self.docker.call("start", record["container"])
                self.wait_ready(record, timeout)
                return self.status(name)
            if config is None:
                raise ValueError("A new deployment requires a profile or deployment configuration")
            image_id = self.docker.call("image", "inspect", image or "deceive:local", "--format", "{{.Id}}")
            prefix = f"deceive-{owner[:12]}-{name}"
            record = {"schema_version": 1, "name": name, "owner": owner, "image": image_id,
                      "container": None, "volume": prefix + "-data", "network": prefix + "-net",
                      "options": options,
                      "created_at": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
                      "config_fingerprint": fingerprint(config.model_dump(mode="json")),
                      'plan_fingerprint': fingerprint({key: fingerprint(value) for key, value in plan.profiles.items()}),
                      "profiles": [{"id": p.id, "version": p.version, "fingerprint": fingerprint(p),
                                    'instance_id': p.instance_id or p.id, 'organization_id': p.organization_id}
                                   for members in plan.members.values() for p in members],
                      "listeners": [], "notes": []}
            stage = directory / ("snapshot-" + uuid.uuid4().hex)
            stage.mkdir(mode=0o755)
            reservations = []
            try:
                deployment, mounts, environment = self.snapshot(config, plan, stage, record,
                    publish_host, publish, env_names, aws_dir, reservations)
                # Validate container bind changes against original profile references before creation.
                translated = config.model_copy(deep=True)
                translated.listeners = [type(listener).model_validate(row | {
                    "profile": listener.profile, "profiles": listener.profiles})
                    for listener, row in zip(plan.listeners, deployment["listeners"])]
                translated.deceptions = []
                validation = Runtime(translated, telemetry=Telemetry("managed-validation", stream=io.StringIO()))
                await validation.close()
                write_json(stage / "deployment.json", deployment, mode=0o644)
                write_json(directory / "record.json", record)
                for kind, resource in (("volume", record["volume"]), ("network", record["network"])):
                    if self.owned(kind, resource, record) is None:
                        self.docker.call(kind, "create", "--label", "deceive.managed=" + owner,
                                         "--label", "deceive.deployment=" + name, resource)
                command = ["create", "--pull", "never", "--name", prefix,
                           "--label", "deceive.managed=" + owner,
                           "--label", "deceive.deployment=" + name,
                           "--network", record["network"], "--cap-drop", "ALL",
                           "--security-opt", "no-new-privileges", "--read-only",
                           "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=16m",
                           "--log-opt", "max-size=10m", "--log-opt", "max-file=3",
                           "--mount", f'type=volume,source={record["volume"]},target=/data',
                           "--mount", self.mount(stage, "/config")]
                for source, destination in mounts:
                    command.extend(["--mount", self.mount(source, destination)])
                for env in sorted(environment):
                    command.extend(["--env", env])
                for listener in record["listeners"]:
                    for binding in listener["bindings"]:
                        command.extend(["--publish", f'{publish_host}:{binding["host_port"]}:{binding["container_port"]}/{binding["transport"]}'])
                command.extend([image_id, "serve", "--config", "/config/deployment.json"])
                if not skip_preflight:
                    command.append('--preflight')
                selected = set(deployment['providers'])
                values = selected_environment(config.providers, selected)
                record["container"] = self.docker.call(*command,
                    **({'env': dict(os.environ) | values} if values else {}))
                write_json(directory / "record.json", record)
                for sock in reservations:
                    sock.close()
                self.docker.call("start", record["container"])
                self.wait_ready(record, timeout)
                return self.status(name)
            except (OSError, ValueError, RuntimeError):
                # Keep the record/data for diagnosis and explicit cleanup; never claim readiness.
                if record["container"]:
                    if self.owned("container", record["container"], record):
                        self.docker.command("stop", "--time", "5", record["container"])
                raise
            finally:
                for sock in reservations:
                    sock.close()

    @staticmethod
    def mount(source: Path, destination: str) -> str:
        if "," in str(source):
            raise ValueError("Docker mount source paths cannot contain commas")
        return f"type=bind,source={source.resolve()},target={destination},readonly"

    def snapshot(self, config: Deployment, plan: Plan, stage: Path, record: dict, host: str,
                 publish: tuple[str, ...] | list[str], env_names: tuple[str, ...] | list[str],
                 aws_dir: Path | None, reservations: list[socket.socket]
                 ) -> tuple[dict, list[tuple[Path, str]], set[str]]:
        overrides = {}
        for value in publish:
            name, separator, port = value.partition("=")
            if not separator or not port.isdecimal() or not 0 <= int(port) <= 65535 or name in overrides:
                raise ValueError("Publish overrides must be unique LISTENER=PORT values (0 allocates a port)")
            overrides[name] = int(port)
        if set(overrides) - {listener.name for listener in plan.listeners}:
            raise ValueError("Publish override names an unknown listener")
        raw = config.model_dump(mode="json")
        raw.update(data_dir="/data", listeners=[], deceptions=[], deception_defaults={},
                   organization=None, default_provider=None)
        if config.log_file:
            raw["log_file"] = "/data/telemetry.jsonl"
            record["notes"].append("Configured file telemetry is retained in the data volume at /data/telemetry.jsonl")
        mounts, environment = [], set(env_names)
        for env in environment:
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", env) or env not in os.environ:
                raise ValueError("Forwarded environment variables must be existing names, without values")
        for index, listener in enumerate(plan.listeners):
            if listener.protocol not in {"ssh", "http", "https"}:
                raise ValueError("This managed backend supports SSH, HTTP and HTTPS bindings; use serve for custom adapters")
            row = listener.model_dump(mode="json")
            row["host"] = "0.0.0.0"
            row["port"] = listener.port or 18080 + index * 2
            if row["port"] < 1024:
                raise ValueError("Use high internal listener ports and --publish LISTENER=PORT for standard external ports")
            for key in ("host_key", "cert_file", "key_file"):
                if row[key]:
                    source = Path(row[key])
                    if not source.is_file():
                        raise ValueError(f"Configured {key} file is missing")
                    row[key] = f"/material/{index}-{key}"
                    mounts.append((source, row[key]))
            references = [plan.references.get(member.instance_id or member.id,
                          listener.profile or listener.profiles[0]) for member in plan.members[listener.name]]
            staged = [snapshot_profile(str(reference), stage, profile=member)
                      for reference, member in zip(references, plan.members[listener.name])]
            row["profile"], row["profiles"] = (staged[0], []) if listener.profile else (None, staged)
            host_port = overrides.get(listener.name, listener.port)
            if not host_port:
                sock, host_port = self.reserve(host, "tcp")
                reservations.append(sock)
            bindings = [{"transport": "tcp", "container_port": row["port"], "host_port": host_port}]
            if listener.protocol == "https" and "3" in listener.versions:
                row["quic_port"] = listener.quic_port or row["port"]
                if row["quic_port"] < 1024:
                    raise ValueError("Use a high internal QUIC port and publish the standard external port")
                udp_port = overrides.get(listener.name, listener.advertised_port or listener.quic_port or listener.port)
                if not udp_port:
                    try:
                        sock, udp_port = self.reserve(host, "udp", host_port)
                    except OSError:
                        sock, udp_port = self.reserve(host, "udp")
                    reservations.append(sock)
                row["advertised_port"] = udp_port
                bindings.append({"transport": "udp", "container_port": row["quic_port"], "host_port": udp_port})
            record["listeners"].append({"name": listener.name, "protocol": listener.protocol,
                "versions": listener.versions if listener.protocol in {"http", "https"} else [],
                "host": host, "bindings": bindings})
            raw["listeners"].append(row)
        selected = {listener.provider for listener in plan.listeners if listener.provider}
        values = selected_environment(config.providers, selected)
        raw["providers"] = {name: value for name, value in raw["providers"].items() if name in selected}
        for name in selected:
            provider = config.providers[name]
            raw['providers'][name]['env_file'] = None
            if provider.api_key_file:
                if not provider.api_key_file.is_file():
                    raise ValueError("Provider secret file is missing")
                target = f"/material/provider-{len(mounts)}"
                mounts.append((provider.api_key_file, target))
                raw["providers"][name]["api_key_file"] = target
            elif provider.api_key_env:
                if provider.api_key_env not in values:
                    raise ValueError(f"Set credential environment variable {provider.api_key_env}")
                environment.add(provider.api_key_env)
            elif provider.api_key is not None:
                variable = literal_name(name)
                raw['providers'][name]['api_key_env'] = variable
                environment.add(variable)
            else:
                environment.update(values)
            if provider.kind == "bedrock" and (provider.aws_profile or values.get('AWS_PROFILE')
                    or values.get('AWS_DEFAULT_PROFILE')) and aws_dir is None:
                raise ValueError("A named AWS profile requires --aws-dir pointing to its local .aws directory")
        if aws_dir:
            if not aws_dir.is_dir():
                raise ValueError("AWS credential directory not found")
            mounts.append((aws_dir, "/home/deceive/.aws"))
        return raw, mounts, environment

    def wait_ready(self, record: dict, timeout: float) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            info = self.owned("container", record["container"], record) if record.get("container") else None
            if info is None or not info["State"].get("Running"):
                raise RuntimeError("Managed listener failed to start; inspect its Docker logs and configuration")
            if self.docker.command("exec", record["container"], "deceive", "healthcheck").returncode == 0:
                actual = info["NetworkSettings"]["Ports"]
                for listener in record["listeners"]:
                    for binding in listener["bindings"]:
                        key = f'{binding["container_port"]}/{binding["transport"]}'
                        expected = {"HostIp": listener["host"], "HostPort": str(binding["host_port"])}
                        if actual.get(key) != [expected]:
                            raise RuntimeError("Docker published ports differ from the validated deployment")
                return
            time.sleep(0.1)
        raise RuntimeError("Managed deployment readiness timed out; its container is retained for diagnosis")

    def stop(self, name: str, *, timeout: int = 30) -> dict:
        if not 1 <= timeout <= 600:
            raise ValueError("Stop timeout must be between 1 and 600 seconds")
        with self.locked(name):
            record = self.record(name)
            info = self.owned("container", record["container"], record) if record.get("container") else None
            if info and info["State"].get("Running"):
                self.docker.call("stop", "--time", str(timeout), record["container"], timeout=timeout + 5)
            return self.status(name)

    def remove(self, name: str, *, remove_data: bool = False) -> dict:
        with self.locked(name) as directory:
            record = self.record(name)
            info = self.owned("container", record["container"], record) if record.get("container") else None
            if info and info["State"].get("Running"):
                raise ValueError("Stop the managed deployment before removing it")
            if info:
                self.docker.call("rm", record["container"])
            if self.owned("network", record["network"], record):
                self.docker.call("network", "rm", record["network"])
            if remove_data and self.owned("volume", record["volume"], record):
                self.docker.call("volume", "rm", record["volume"])
            (directory / "record.json").unlink()
            return {"name": name, "removed": True, "data_retained": not remove_data,
                    "volume": record["volume"], "state_dir": str(directory)}
