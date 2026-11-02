from __future__ import annotations

from configparser import ConfigParser
from pathlib import Path

import yaml

from deceive.material import exclusive_write


def migrate(source: Path, destination: Path) -> list[str]:
    source = source.resolve()
    parser = ConfigParser(interpolation=None)
    if not parser.read(source):
        raise ValueError("Legacy INI file does not exist")
    if not parser.has_section("ssh"):
        raise ValueError("Migration accepts the legacy SSH INI configuration")
    outputs = [destination / name for name in ("deployment.yaml", "profile.yaml", "migration-report.txt")]
    if any(path.exists() for path in outputs):
        raise ValueError("Migration outputs already exist; choose a new output directory")
    ssh = dict(parser["ssh"])
    llm = dict(parser["llm"]) if parser.has_section("llm") else {}
    honeypot = dict(parser["honeypot"]) if parser.has_section("honeypot") else {}
    reports = [
        "Original INI was not modified.",
        "History now has conservative byte/token budgets and turn limits; token trimming semantics changed.",
        "The runtime renders SSH prompts/MOTD. Review legacy prompt instructions for conflicting formatting.",
        "Generative identity details must be configured explicitly for consistency across connections.",
    ]
    kind = llm.get("llm_provider", "openai").lower()
    kind = "bedrock" if kind == "aws" else kind
    if kind not in {"openai", "azure", "bedrock", "gemini", "ollama"}:
        raise ValueError(f"Unsupported legacy provider {kind}")
    provider = {"kind": kind, "model": llm.get("model_name", "gpt-4o-mini"),
                "temperature": float(llm.get("temperature", "0.2")),
                "tls_verify": llm.get("tls_verify", "true").lower() not in {"false", "0", "no"}}
    mappings = {"azure_endpoint": "endpoint", "azure_api_version": "api_version",
                "aws_region": "region", "aws_credentials_profile": "aws_profile"}
    for old, new in mappings.items():
        if old in llm:
            provider[new] = llm[old]
    if kind == "azure" and llm.get("azure_deployment"):
        provider["model"] = llm["azure_deployment"]
    listener = {"name": "main", "protocol": "ssh", "profile": "profile.yaml",
                "host": ssh.get("listen_host", "0.0.0.0"), "port": int(ssh.get("port", "8022")),
                "provider": "default", "analyze": True,
                "accounts": dict(parser["user_accounts"]) if parser.has_section("user_accounts") else {}}
    if ssh.get("host_priv_key"):
        key = Path(ssh["host_priv_key"])
        candidate = key if key.is_absolute() else source.parent / key
        if not candidate.exists():
            fallback = Path(__file__).resolve().parent.parent / "SSH" / key
            if fallback.exists():
                candidate = fallback
        listener["host_key"] = str(candidate.resolve())
    profile = {"schema_version": 1, "id": "migrated-ssh", "version": "1", "protocol": "ssh",
               "identity": {"ssh_version": ssh.get("server_version_string", "OpenSSH_8.9p1")
                            .removeprefix("SSH-2.0-")},
               "behaviors": [{"id": "identity", "kind": "identity"}], "fallback": "llm",
               "prompt": llm.get("system_prompt", "")}
    prompt_file = source.parent / "prompt.txt"
    if prompt_file.is_file():
        profile["prompt"] += "\n" + prompt_file.read_text()
    deployment = {"schema_version": 1, "data_dir": "data",
                  "sensor_name": honeypot.get("sensor_name", "deceive"),
                  "providers": {"default": provider}, "listeners": [listener]}
    if honeypot.get("log_file"):
        log = Path(honeypot["log_file"])
        deployment["log_file"] = str((source.parent / log).resolve())
    if "trimmer_max_tokens" in llm:
        deployment["limits"] = {"history_tokens": max(128, int(llm["trimmer_max_tokens"]))}
    known = {
        "ssh": {"port", "listen_host", "host_priv_key", "server_version_string"},
        "honeypot": {"sensor_name", "log_file"},
        "llm": {"llm_provider", "model_name", "temperature", "system_prompt", "tls_verify",
                "trimmer_max_tokens", "azure_deployment", *mappings},
        "user_accounts": set(dict(parser["user_accounts"])) if parser.has_section("user_accounts") else set(),
    }
    for section in parser.sections():
        for key in parser[section]:
            if key not in known.get(section, set()):
                reports.append(f"Manual review: unsupported setting [{section}].{key}; value not copied.")
    destination.mkdir(parents=True, exist_ok=True)
    exclusive_write(outputs[0], yaml.safe_dump(deployment, sort_keys=False).encode())
    exclusive_write(outputs[1], yaml.safe_dump(profile, sort_keys=False).encode())
    exclusive_write(outputs[2], ("\n".join(reports) + "\n").encode())
    return reports
