from __future__ import annotations

from pathlib import Path
import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Identity(Model):
    hostname: str = Field(default="build-node-03", pattern=r"^[A-Za-z0-9][A-Za-z0-9.-]{0,62}$")
    os: str = "Ubuntu 22.04.5 LTS"
    kernel: str = "5.15.0-130-generic"
    architecture: str = "x86_64"
    uid: int = Field(default=1000, ge=0)
    username: str = "guest"
    ssh_version: str = "OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"
    banner: str = "Welcome to the build server."


class Match(Model):
    command: str | None = None
    command_regex: str | None = Field(default=None, max_length=1024)
    path: str | None = None
    method: str | None = None
    headers: dict[str, str] = Field(default_factory=dict)
    body_contains: str | None = None
    state: dict[str, str] = Field(default_factory=dict)


class Reply(Model):
    body: str = ""
    body_base64: str | None = None
    body_file: str | None = None
    status: int = Field(default=200, ge=200, le=599)
    headers: list[tuple[str, str]] = Field(default_factory=list)
    close: bool = False
    exit_status: int = Field(default=0, ge=0, le=255)

    @model_validator(mode="after")
    def valid_content(self) -> Reply:
        if sum((bool(self.body), self.body_base64 is not None, self.body_file is not None)) > 1:
            raise ValueError("Choose only one of body, body_base64, and body_file")
        for name, value in self.headers:
            if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name) or any(c in value for c in "\r\n\x00"):
                raise ValueError("Invalid response header")
            try:
                name.encode("ascii")
                value.encode("latin-1")
            except UnicodeEncodeError as exc:
                raise ValueError("Headers must be ASCII names and Latin-1 values") from exc
        return self


class Behavior(Model):
    id: str
    kind: str = "rule"
    match: Match = Field(default_factory=Match)
    reply: Reply = Field(default_factory=Reply)
    transition: dict[str, str] = Field(default_factory=dict)
    options: dict[str, Any] = Field(default_factory=dict)


class Requirements(Model):
    protocol: str = Field(min_length=1)
    http_versions: list[Literal["1.1", "2", "3"]] = Field(default_factory=lambda: ["1.1"])
    base_profile: str | None = None
    base_version: str | None = None
    preferred_port: int | None = Field(default=None, ge=1, le=65535)
    required_port: int | None = Field(default=None, ge=1, le=65535)
    capabilities: list[str] = Field(default_factory=list)
    incompatible_with: list[str] = Field(default_factory=list)
    scope: Literal["request", "session", "connection"] = "request"

    @model_validator(mode="after")
    def valid_requirements(self) -> Requirements:
        if bool(self.base_profile) != bool(self.base_version):
            raise ValueError("base_profile and exact base_version must be supplied together")
        if not self.http_versions:
            raise ValueError("http_versions cannot be empty")
        if "3" in self.http_versions and self.protocol != "https":
            raise ValueError("HTTP/3 requirements need protocol https")
        return self


class Profile(Model):
    schema_version: Literal[1] = 1
    id: str
    version: str = "1"
    description: str = ""
    protocol: str = Field(min_length=1)
    http_versions: list[Literal["1.1", "2", "3"]] = Field(default_factory=lambda: ["1.1"])
    identity: Identity = Field(default_factory=Identity)
    files: dict[str, str] = Field(default_factory=dict)
    prompt: str = ""
    prompt_file: str | None = None
    behaviors: list[Behavior] = Field(default_factory=list)
    fallback: Literal["reject", "llm"] = "reject"
    fallback_reply: Reply = Field(default_factory=lambda: Reply(body="Not found\n", status=404))
    stateful: bool = False
    cookie_name: str = "session"
    references: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    requirements: Requirements | None = None

    @model_validator(mode="before")
    @classmethod
    def derive_protocol(cls, value: Any) -> Any:
        if isinstance(value, dict) and isinstance(value.get("requirements"), dict):
            value = dict(value)
            requirements = value["requirements"]
            protocol = requirements.get("protocol")
            value.setdefault("protocol", "http" if protocol == "https" else protocol)
            value.setdefault("http_versions", requirements.get("http_versions", ["1.1"]))
        return value

    @model_validator(mode="after")
    def valid_profile(self) -> Profile:
        if len({b.id for b in self.behaviors}) != len(self.behaviors):
            raise ValueError("Behavior IDs must be unique")
        if not self.http_versions:
            raise ValueError("http_versions cannot be empty")
        if self.prompt and self.prompt_file:
            raise ValueError("Choose prompt or prompt_file, not both")
        if not self.cookie_name or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for c in self.cookie_name):
            raise ValueError("cookie_name must be an HTTP token")
        if any(not p.startswith("/") for p in self.files):
            raise ValueError("Virtual file paths must be absolute")
        inherited_hostname = (self.requirements and self.requirements.base_profile
                              and "hostname" not in self.identity.model_fields_set)
        if (not inherited_hostname and "/etc/hostname" in self.files
                and self.files["/etc/hostname"].strip() != self.identity.hostname):
            raise ValueError("/etc/hostname must match identity.hostname")
        if self.requirements:
            protocol = self.requirements.protocol
            if self.protocol != ("http" if protocol == "https" else protocol):
                raise ValueError("profile protocol contradicts requirements.protocol")
            if set(self.http_versions) != set(self.requirements.http_versions):
                raise ValueError("profile http_versions contradict requirements.http_versions")
        return self


class Limits(Model):
    input_bytes: int = Field(default=16384, ge=128, le=1048576)
    body_bytes: int = Field(default=1048576, ge=128, le=16777216)
    output_bytes: int = Field(default=1048576, ge=128, le=16777216)
    sessions: int = Field(default=100, ge=1, le=10000)
    requests: int = Field(default=32, ge=1, le=1000)
    idle_seconds: float = Field(default=300, gt=0)
    total_seconds: float = Field(default=1800, gt=0)
    request_seconds: float = Field(default=30, gt=0)
    llm_seconds: float = Field(default=25, gt=0)
    llm_concurrency: int = Field(default=4, ge=1, le=100)
    history_turns: int = Field(default=32, ge=1, le=1000)
    history_bytes: int = Field(default=65536, ge=128, le=4194304)
    history_tokens: int = Field(default=12000, ge=128)
    observer_queue: int = Field(default=128, ge=1, le=10000)


class ProviderConfig(Model):
    kind: Literal["openai", "azure", "ollama", "bedrock", "gemini"]
    model: str
    api_key_env: str | None = None
    api_key_file: Path | None = None
    endpoint: str | None = None
    api_version: str | None = None
    region: str | None = None
    aws_profile: str | None = None
    temperature: float | None = 0.2
    max_output_tokens: int = Field(default=2048, ge=1, le=32768)
    context_tokens: int = Field(default=16384, ge=1024)
    tls_verify: bool = True

    @model_validator(mode="after")
    def valid_provider(self) -> ProviderConfig:
        if not self.model.strip():
            raise ValueError("model cannot be empty")
        if self.kind == "bedrock" and (self.api_key_env or self.api_key_file):
            raise ValueError("Bedrock uses the AWS credential chain; mount AWS_SHARED_CREDENTIALS_FILE")
        if self.max_output_tokens + 256 >= self.context_tokens:
            raise ValueError("context_tokens must leave room for input and max_output_tokens")
        return self


class Listener(Model):
    name: str = "main"
    protocol: str = Field(min_length=1)
    profile: str | None = None
    profiles: list[str] = Field(default_factory=list)
    host: str = "0.0.0.0"
    port: int = Field(default=8080, ge=0, le=65535)
    versions: list[Literal["1.1", "2", "3"]] = Field(default_factory=lambda: ["1.1"])
    quic_port: int | None = Field(default=None, ge=0, le=65535)
    advertised_port: int | None = Field(default=None, ge=1, le=65535)
    host_key: Path | None = None
    cert_file: Path | None = None
    key_file: Path | None = None
    provider: str | None = None
    analyze: bool = False
    enabled: bool = True
    accounts: dict[str, str] = Field(default_factory=lambda: {"guest": "", "root": "*"})

    @model_validator(mode="after")
    def valid_listener(self) -> Listener:
        if bool(self.profile) == bool(self.profiles):
            raise ValueError("Choose one profile or a non-empty profiles list")
        if "3" in self.versions and self.protocol != "https":
            raise ValueError("HTTP/3 requires an https listener")
        if not self.versions:
            raise ValueError("versions cannot be empty")
        if (self.cert_file is None) != (self.key_file is None):
            raise ValueError("cert_file and key_file must be supplied together")
        if self.analyze and self.provider is None:
            raise ValueError("LLM analysis requires provider")
        if not self.name or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for c in self.name):
            raise ValueError("Listener name must use letters, digits, underscores or hyphens")
        return self


class Deception(Model):
    profile: str


class DeceptionDefaults(Model):
    host: str = "0.0.0.0"
    provider: str | None = None
    analyze: bool = False


class Deployment(Model):
    schema_version: Literal[1] = 1
    data_dir: Path = Path(".deceive")
    sensor_name: str = "deceive"
    log_file: Path | None = None
    limits: Limits = Field(default_factory=Limits)
    providers: dict[str, ProviderConfig] = Field(default_factory=dict)
    listeners: list[Listener] = Field(default_factory=list)
    deceptions: list[Deception] = Field(default_factory=list)
    deception_defaults: DeceptionDefaults = Field(default_factory=DeceptionDefaults)
    extensions: dict[str, list[str]] = Field(default_factory=dict)

    @model_validator(mode="after")
    def valid_deployment(self) -> Deployment:
        if len({x.name for x in self.listeners}) != len(self.listeners):
            raise ValueError("Listener names must be unique")
        if not any(x.enabled for x in self.listeners) and not self.deceptions:
            raise ValueError("At least one listener must be enabled")
        if self.deception_defaults.provider and self.deception_defaults.provider not in self.providers:
            raise ValueError(f"Unknown provider '{self.deception_defaults.provider}'")
        if self.deception_defaults.analyze and not self.deception_defaults.provider:
            raise ValueError("LLM analysis requires provider")
        for listener in self.listeners:
            if listener.provider and listener.provider not in self.providers:
                raise ValueError(f"Unknown provider '{listener.provider}'")
        if set(self.extensions) - {"protocols", "behaviors", "observers"}:
            raise ValueError("Unknown extension group")
        return self
