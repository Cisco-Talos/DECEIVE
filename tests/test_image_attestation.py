import json
import subprocess

import pytest

from deceive.assessment.docker import Docker
from deceive.assessment.models import Spec


def test_installed_source_attestation_rejects_stale_or_missing_files(monkeypatch):
    docker = Docker()
    monkeypatch.setattr(docker, "call", lambda *args, **kwargs: json.dumps({
        "deceive/runtime.py": "old", "deceive/vulnerabilities.py": None}))
    with pytest.raises(RuntimeError, match="Installed image source"):
        docker.verify_image("image", {"deceive/runtime.py": "new", "deceive/vulnerabilities.py": "new"})


def test_built_image_checks_runtime_sources_without_rebuilding_for_client_files(tmp_path, monkeypatch):
    docker = Docker()
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: subprocess.CompletedProcess([], 0))
    monkeypatch.setattr(docker, "call", lambda *args, **kwargs: "sha256:image")
    verified = []

    def verify(image, expected):
        verified.append(expected)
        return {"matched": True, "checked": len(expected)}

    monkeypatch.setattr(docker, "verify_image", verify)
    candidate = {"server_id": "fingerprint", "files": {
        "deceive/runtime.py": "runtime", "deceive/vulnerabilities.py": "behavior",
        "deceive/clients.py": "client", "deceive/evaluate.py": "evaluation",
        "deceive/assessment/engine.py": "controller", "deceive/profiles/demo-http.yaml": "mounted",
        "tests/test_runtime.py": "test"}}
    spec = Spec(targets=[{"name": "web", "profiles": ["demo-http"]}])
    assert docker.image(spec, candidate, tmp_path) == "sha256:image"
    assert verified == [{"deceive/runtime.py": "runtime", "deceive/vulnerabilities.py": "behavior"}]
    assert json.loads((tmp_path / "image-attestation.json").read_text())["matched"]
