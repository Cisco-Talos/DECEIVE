"""Read-only discovery of packaged and operator-authored profiles."""
from __future__ import annotations

from importlib.resources import files
from collections.abc import Sequence
from pathlib import Path
import re

from deceive.composition import _compose
from deceive.config import fingerprint, load_profile
from deceive.models import Profile
from deceive.vulnerabilities import CVE_HANDLERS


def entry(reference: str, profile: Profile) -> dict:
    effective, _ = _compose([profile])
    requirements = profile.requirements
    return {"id": profile.id, "version": profile.version, "reference": reference,
            "description": profile.description,
            "protocol": requirements.protocol if requirements else profile.protocol,
            "http_versions": effective.http_versions if profile.protocol == "http" else [],
            "fallback": effective.fallback,
            "ssh_response_format": effective.ssh_response_format if profile.protocol == "ssh" else None,
            "behavior_kinds": sorted({b.kind for b in effective.behaviors}),
            "base_profile": requirements.base_profile if requirements else None,
            "base_version": requirements.base_version if requirements else None,
            "fingerprint": fingerprint(profile),
            "vulnerability": any(b.kind in CVE_HANDLERS for b in effective.behaviors)
                or any(re.search(r"CVE-\d{4}-\d+", ref, re.I) for ref in profile.references),
            "references": profile.references, "limitations": profile.limitations}


def profiles(directories: Sequence[Path] = ()) -> list[dict]:
    references = [str(asset) for asset in sorted(files("deceive").joinpath("profiles").iterdir(),
                                                key=lambda asset: asset.name)
                  if asset.name.endswith(".yaml")]
    for directory in directories:
        if not directory.is_dir():
            raise ValueError(f"Profile directory not found: {directory}")
        references.extend(str(path.resolve()) for path in sorted(directory.iterdir())
                          if path.is_file() and path.suffix in {".yaml", ".yml"})
    found = {}
    for reference in references:
        profile = load_profile(reference)
        row = entry(reference, profile)
        previous = found.get(profile.id)
        if previous and previous["fingerprint"] != row["fingerprint"]:
            raise ValueError(f"Conflicting profile definitions for id '{profile.id}'")
        found.setdefault(profile.id, row)
    return [found[name] for name in sorted(found)]


def show(reference: str, directories: Sequence[Path] = (), *, organization: Path | None = None) -> dict:
    if not Path(reference).is_file():
        matches = [row for row in profiles(directories) if row["id"] == reference]
        if not matches:
            raise ValueError(f"Profile not found in catalog: {reference}")
        reference = matches[0]["reference"]
    profile = load_profile(reference, organization=organization)
    effective, _ = _compose([profile])
    return entry(reference, profile) | {
        "definition": profile.model_dump(mode="json", exclude_unset=True),
        "effective_identity": effective.identity.model_dump(mode="json"),
        "instance_id": profile.instance_id or profile.id,
        "organization_id": profile.organization_id,
        "parameters": {k: {'definition': v.model_dump(), 'value': profile.resolved_parameters.get(k),
                           'origin': profile.parameter_origins.get(k)} for k, v in profile.parameters.items()},
        "contracts": [c.model_dump(mode='json') for c in effective.contracts],
        "effective_files": effective.files}
