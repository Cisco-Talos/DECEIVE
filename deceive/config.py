from __future__ import annotations

import base64
import hashlib
from importlib.resources import files
import json
from pathlib import Path
import re

import yaml
import regex

from deceive.models import Deployment, Profile


class UniqueLoader(yaml.SafeLoader):
    """Reject duplicate keys rather than silently replacing operator settings."""


def _mapping(loader: UniqueLoader, node: yaml.MappingNode) -> dict:
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node)
        if not isinstance(key, (str, int, float, bool)) or key in result:
            raise ValueError("YAML mapping contains an invalid or duplicate key")
        result[key] = loader.construct_object(value_node)
    return result


UniqueLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _mapping)


def read_yaml(path: Path) -> dict:
    if path.stat().st_size > 4 * 1024 * 1024:
        raise ValueError("YAML file exceeds 4 MiB")
    try:
        value = yaml.load(path.read_text(), Loader=UniqueLoader)
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid YAML in {path.name}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{path.name} must contain a YAML mapping")
    return value


def relative_path(base: Path, value: str | Path) -> Path:
    path = Path(value).expanduser()
    return path.resolve() if path.is_absolute() else (base / path).resolve()


def load_profile(reference: str, base: Path | None = None) -> Profile:
    base = base or Path.cwd()
    path = relative_path(base, reference)
    if not path.is_file() and re.fullmatch(r"[a-z0-9-]+", reference):
        resource = files("deceive").joinpath("profiles", reference + ".yaml")
        if resource.is_file():
            path = Path(str(resource))
    if not path.is_file():
        raise ValueError(f"Profile not found: {reference}")
    profile = Profile.model_validate(read_yaml(path))
    if profile.requirements and profile.requirements.base_profile:
        reference = profile.requirements.base_profile
        candidate = relative_path(path.parent, reference)
        if candidate.is_file() or "/" in reference or reference.endswith((".yaml", ".yml")):
            profile.requirements.base_profile = str(candidate)
    if profile.prompt_file:
        prompt = relative_path(path.parent, profile.prompt_file)
        if prompt.stat().st_size > 1048576:
            raise ValueError("Prompt file exceeds 1 MiB")
        profile.prompt = prompt.read_text()
        profile.prompt_file = None
    replies = [behavior.reply for behavior in profile.behaviors] + [profile.fallback_reply]
    for reply in replies:
        if reply.body_file:
            asset = relative_path(path.parent, reply.body_file)
            if asset.stat().st_size > 1048576:
                raise ValueError("Response asset exceeds 1 MiB")
            reply.body_base64 = base64.b64encode(asset.read_bytes()).decode()
            reply.body_file = None
        if reply.body_base64 is not None:
            base64.b64decode(reply.body_base64, validate=True)
    for behavior in profile.behaviors:
        if behavior.match.command_regex:
            try:
                regex.compile(behavior.match.command_regex)
            except regex.error as exc:
                raise ValueError(f"Invalid command pattern in behavior {behavior.id}") from exc
    # Validation of engine capabilities is performed by the runtime's registry.
    return profile


def fingerprint(model: Profile | dict | list) -> str:
    value = model.model_dump(mode="json") if isinstance(model, Profile) else model
    if isinstance(model, Profile) and model.requirements and model.requirements.base_profile:
        # An explicit default is a constraint; omission means inheritance. Keep
        # that distinction when deduplicating and identifying compositions.
        value["composition_constraints"] = {
            "identity": model.identity.model_dump(include=model.identity.model_fields_set),
            "settings": {key: value[key] for key in ("fallback", "fallback_reply", "cookie_name")
                         if key in model.model_fields_set},
        }
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def load_deployment(path: Path, *, additional_profiles: list[str] | None = None) -> Deployment:
    raw = read_yaml(path)
    if additional_profiles:
        selections = raw.get("deceptions", [])
        if not isinstance(selections, list):
            raise ValueError("deceptions must be a list")
        raw["deceptions"] = selections + [
            {"profile": _profile_reference(Path.cwd(), ref)} for ref in additional_profiles]
    base = path.resolve().parent
    deployment = Deployment.model_validate(raw)
    deployment.data_dir = relative_path(base, deployment.data_dir)
    if deployment.log_file:
        deployment.log_file = relative_path(base, deployment.log_file)
    for provider in deployment.providers.values():
        if provider.api_key_file:
            provider.api_key_file = relative_path(base, provider.api_key_file)
    for listener in deployment.listeners:
        if listener.profile:
            listener.profile = _profile_reference(base, listener.profile)
        listener.profiles = [_profile_reference(base, ref) for ref in listener.profiles]
        for field in ("host_key", "cert_file", "key_file"):
            value = getattr(listener, field)
            if value:
                setattr(listener, field, relative_path(base, value))
    for deception in deployment.deceptions:
        deception.profile = _profile_reference(base, deception.profile)
    return deployment


def _profile_reference(base: Path, reference: str) -> str:
    candidate = relative_path(base, reference)
    if candidate.is_file() or "/" in reference or reference.endswith((".yaml", ".yml")):
        return str(candidate)
    return reference
