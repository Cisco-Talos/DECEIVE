"""Prove a warm Docker/uv build installs source-only changes without metadata changes."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import tempfile
import uuid

from deceive.assessment.docker import Docker
from deceive.assessment.workspace import checkpoint


def verify(image: str, root: Path) -> dict:
    docker = Docker()
    module = "deceive/vulnerabilities.py"
    baseline = hashlib.sha256((root / module).read_bytes()).hexdigest()
    docker.verify_image(image, {module: baseline})
    tag = "deceive-rebuild-smoke:" + uuid.uuid4().hex[:12]
    built = False
    try:
        with tempfile.TemporaryDirectory(prefix="deceive-image-rebuild-") as directory:
            checkpoint(root, Path(directory))
            context = Path(directory) / "source"
            metadata = {name: (context / name).read_bytes() for name in (
                "pyproject.toml", "uv.lock", "Dockerfile", "README.md", "LICENSE")}
            source = context / module
            source.write_bytes(source.read_bytes() + b"\n_BUILD_CACHE_SOURCE_PROBE = True\n")
            changed = hashlib.sha256(source.read_bytes()).hexdigest()
            assert changed != baseline
            assert all((context / name).read_bytes() == contents for name, contents in metadata.items())
            docker.call("build", "-t", tag, str(context), timeout=900)
            built = True
            digest = docker.call("image", "inspect", tag, "--format", "{{.Id}}")
            attestation = docker.verify_image(digest, {module: changed})
            return {"passed": True, "metadata_unchanged": True, "baseline_module_sha256": baseline,
                    "rebuilt_module_sha256": changed, "image": digest,
                    "source_only_change_installed": attestation["matched"]}
    finally:
        if built:
            docker.call("image", "rm", tag)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("image")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--report", type=Path, default=Path("container-rebuild.json"))
    args = parser.parse_args()
    result = verify(args.image, args.root.resolve())
    args.report.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result))
