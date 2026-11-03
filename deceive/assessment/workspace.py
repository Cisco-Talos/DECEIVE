from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
from importlib.resources import files
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
import uuid

from deceive.assessment.models import Spec, Target
from deceive.config import fingerprint, load_deployment, load_profile, read_yaml, relative_path
from deceive.models import Deception, Deployment

CLIENT_FILES = {"deceive/clients.py", "deceive/evaluate.py", "deceive/catalog.py", "deceive/managed.py"}


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def write_json(path: Path, value: dict | list) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n")
    temporary.chmod(0o600)
    temporary.replace(path)


def load_json(path: Path) -> dict:
    return json.loads(path.read_text())


@contextmanager
def locked(run: Path):
    with (run / "controller.lock").open("a") as stream:
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ValueError("Another assessment command is modifying this run") from exc
        yield


def git(root: Path, *args: str) -> str:
    result = subprocess.run(["git", "-C", str(root), *args], capture_output=True,
                            text=True, timeout=20, check=True)
    return result.stdout


def resolve_spec(path: Path) -> Spec:
    spec = Spec.model_validate(read_yaml(path))
    base = path.resolve().parent
    if spec.docker.aws_dir is not None:
        spec.docker.aws_dir = relative_path(base, spec.docker.aws_dir)
    for target in spec.targets:
        if target.deployment:
            target.deployment = str(relative_path(base, target.deployment))
        if target.suite:
            target.suite = str(relative_path(base, target.suite))
        target.profiles = [str(relative_path(base, ref)) if
                           "/" in ref or ref.endswith((".yaml", ".yml")) else ref
                           for ref in target.profiles]
    for provider in spec.providers.values():
        if provider.api_key_file:
            provider.api_key_file = relative_path(base, provider.api_key_file)
    if spec.all_profiles:
        existing = {p for t in spec.targets for p in t.profiles}
        for asset in sorted(files("deceive").joinpath("profiles").iterdir(), key=lambda p: p.name):
            if asset.name.endswith(".yaml"):
                name = asset.name.removesuffix(".yaml")
                if name not in existing:
                    spec.targets.append(Target(name="catalog-" + name, profiles=[name]))
    return spec


def target_deployment(spec: Spec, target: Target) -> Deployment:
    if target.deployment:
        config = load_deployment(Path(target.deployment))
    else:
        config = Deployment(deceptions=[Deception(profile=p) for p in target.profiles],
                            providers=spec.providers,
                            deception_defaults={"provider": target.provider})
    return config


def source_files(root: Path) -> list[Path]:
    names = {"pyproject.toml", "uv.lock", "Dockerfile", ".dockerignore", "README.md", "LICENSE", "hatch_build.py"}
    assets = list((root / "docs").glob("*.md")) + list((root / "examples").glob("*.yaml"))
    assets += list((root / "examples/profiles").glob("*.yaml"))
    assets = [p for p in assets if not p.name.startswith(".")]
    return sorted([p for p in root.iterdir() if p.is_file() and p.name in names] + assets + [
        p for folder in ("deceive", "tests", "skills")
        for p in (root / folder).rglob("*") if p.is_file() and
        "__pycache__" not in p.parts and p.suffix not in {".pyc", ".key", ".pem"}
        and not p.name.endswith("_host_key")
        and not any(part.startswith(".") for part in p.relative_to(root).parts)])


def packaged_assets(hashes: dict[str, str]) -> dict[str, str]:
    return {"deceive/_skill_assets/" + name: digest for name, digest in hashes.items()
            if name.startswith(("skills/", "docs/", "examples/"))
            or name in {"README.md", "LICENSE"}}


def checkpoint(root: Path, destination: Path) -> dict:
    hashes = {}
    for path in source_files(root):
        relative = path.relative_to(root)
        data = path.read_bytes()
        hashes[str(relative)] = hashlib.sha256(data).hexdigest()
        output = destination / "source" / relative
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(data)
    patch = git(root, "diff", "--binary", "HEAD")
    (destination / "working-tree.patch").write_text(patch)
    (destination / "working-tree.patch").chmod(0o600)
    server = {k: v for k, v in hashes.items() if not k.startswith((
        "deceive/assessment/", "deceive/profiles/", "deceive/acceptance/", "tests/"))
        and k not in CLIENT_FILES}
    return {"files": hashes, "source_id": fingerprint(hashes),
            "server_id": fingerprint(server), "client_id": fingerprint({
                k: v for k, v in hashes.items() if k.startswith("deceive/assessment/")
                or k in CLIENT_FILES}),
            "review_id": fingerprint({k: v for k, v in hashes.items() if k.startswith("skills/")}),
            "checks_id": fingerprint({k: v for k, v in hashes.items() if k.startswith("tests/")}),
            "branch": git(root, "branch", "--show-current").strip(),
            "head": git(root, "rev-parse", "HEAD").strip()}


def prepare(spec_path: Path, run: Path, root: Path) -> dict:
    if run.exists():
        raise ValueError("Assessment directory already exists; use resume/status or a new directory")
    spec = resolve_spec(spec_path)
    run.mkdir(parents=True, mode=0o700)
    run.chmod(0o700)
    baseline = run / "baseline"
    baseline.mkdir()
    source = checkpoint(root, baseline)
    state = {"schema_version": 1, "run_id": "assess-" + uuid.uuid4().hex[:12],
             "created": now(), "started_epoch": time.time(), "root": str(root.resolve()),
             "spec": spec.model_dump(mode="json"), "baseline": source, "phase": "prepared",
             "loops": [], "current": None, "containers": {}, "stop_reason": None,
             "native_agent_usage": None}
    from deceive.assessment.models import AssessmentRun
    AssessmentRun.model_validate(state)
    write_json(run / "state.json", state)
    return state


def profile_path(reference: str, base: Path | None = None) -> Path:
    path = relative_path(base or Path.cwd(), reference)
    if path.is_file():
        return path
    resource = files("deceive").joinpath("profiles", reference + ".yaml")
    if not resource.is_file():
        raise ValueError(f"Profile not found: {reference}")
    return Path(str(resource))


def stage_profile(reference: str, stage: Path, *, base: Path | None = None,
                  seen: tuple[Path, ...] = ()) -> str:
    path = profile_path(reference, base)
    if path in seen or len(seen) > 10:
        raise ValueError("Cyclic/deep profile dependencies")
    raw = read_yaml(path)
    identity = raw.get("id", "")
    if not re.fullmatch(r"[a-z][a-z0-9_-]{0,127}", identity):
        raise ValueError(f"Assessment requires a safe readable profile id: {path.name}")
    # Preserve omission/inheritance: never round-trip through a full model dump.
    for owner, key in [(raw, "prompt_file")] + [
        (b.get("reply") or {}, "body_file") for b in raw.get("behaviors", [])] + [
        (raw.get("fallback_reply") or {}, "body_file")]:
        if owner.get(key):
            asset = relative_path(path.parent, owner[key])
            data = asset.read_bytes()
            if len(data) > 1048576:
                raise ValueError("Assessment profile asset exceeds 1 MiB")
            name = "asset-" + hashlib.sha256(data).hexdigest()[:20]
            (stage / name).write_bytes(data)
            (stage / name).chmod(0o644)
            owner[key] = "/stage/" + name
    requirements = raw.get("requirements") or {}
    if requirements.get("base_profile"):
        requirements["base_profile"] = stage_profile(requirements["base_profile"], stage,
            base=path.parent, seen=seen + (path,))
    name = "profile-" + fingerprint(raw)[:20] + ".yaml"
    output = stage / name
    output.write_text(json.dumps(raw, indent=2))
    output.chmod(0o644)
    return "/stage/" + name
