from __future__ import annotations

import base64
from pathlib import Path
import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, SecretStr, model_validator


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


class Parameter(Model):
    type: Literal["string", "integer", "number", "boolean"] = "string"
    default: Any
    description: str = ""
    enum: list[Any] | None = None
    minimum: float | None = None
    maximum: float | None = None
    pattern: str | None = Field(default=None, max_length=1024)
    max_length: int = Field(default=4096, ge=1, le=1048576)

    def check(self, value: Any) -> Any:
        valid = {"string": type(value) is str, "integer": type(value) is int,
                 "number": type(value) in (int, float), "boolean": type(value) is bool}
        if not valid[self.type]:
            raise ValueError(f"Expected parameter type {self.type}")
        if self.enum is not None and not any(type(value) is type(v) and value == v for v in self.enum):
            raise ValueError("Parameter is outside its enum")
        if isinstance(value, str):
            if len(value) > self.max_length:
                raise ValueError("Parameter exceeds max_length")
            if self.pattern:
                import regex
                if not regex.fullmatch(self.pattern, value, timeout=0.05):
                    raise ValueError("Parameter does not match pattern")
        elif type(value) in (int, float):
            import math
            if not math.isfinite(value) or (self.minimum is not None and value < self.minimum) or (
                self.maximum is not None and value > self.maximum
            ):
                raise ValueError("Parameter is outside numeric bounds")
        return value

    @model_validator(mode="after")
    def valid_default(self) -> Parameter:
        if self.pattern:
            import regex
            try:
                regex.compile(self.pattern)
            except regex.error as exc:
                raise ValueError('Invalid parameter pattern') from exc
        self.check(self.default)
        return self


class Organization(Model):
    schema_version: Literal[1] = 1
    id: str = Field(pattern=r"^[a-z][a-z0-9_-]*$")
    version: str = "1"
    values: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode='after')
    def scalar_values(self) -> Organization:
        if any(type(v) not in (str, int, float, bool) for v in self.values.values()):
            raise ValueError('Organization values must be scalar strings, numbers or booleans')
        return self


class Selection(Model):
    profile: str
    id: str | None = Field(default=None, pattern=r"^[a-z][a-z0-9_-]*$")
    organization: Path | None = None
    parameters: dict[str, Any] = Field(default_factory=dict)


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
    stderr: str = ""
    stderr_base64: str | None = None
    body_json: Any = None

    @model_validator(mode="after")
    def valid_content(self) -> Reply:
        if sum((bool(self.body), self.body_base64 is not None, self.body_file is not None,
                self.body_json is not None)) > 1:
            raise ValueError("Choose only one of body, body_base64, and body_file")
        if self.stderr_base64 is not None:
            if self.stderr:
                raise ValueError("Choose only one of stderr and stderr_base64")
            base64.b64decode(self.stderr_base64, validate=True)
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


class Checks(Model):
    text: str | None = None
    body_base64: str | None = None
    contains: list[str] = Field(default_factory=list)
    pattern: str | None = Field(default=None, max_length=1024)
    status: int | None = None
    stderr: str | None = None
    exit_status: int | None = None
    headers: list[tuple[str, str]] = Field(default_factory=list)
    json_fields: dict[str, Any] = Field(default_factory=dict)
    json_types: dict[str, Literal["string", "integer", "number", "boolean", "object", "array", "null"]] = Field(default_factory=dict)


class Effects(Model):
    state: dict[str, str] = Field(default_factory=dict)
    write_files: dict[str, str] = Field(default_factory=dict)
    remove_files: list[str] = Field(default_factory=list)


class HTTPMatch(Model):
    path: str
    method: str = "GET"
    query: dict[str, str] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    cookies: dict[str, str] = Field(default_factory=dict)
    body_contains: str | None = None
    json_fields: dict[str, Any] = Field(default_factory=dict)
    json_duplicates: Literal['reject', 'last'] = 'reject'


class CommandMatch(Model):
    program: str
    args: list[str] = Field(default_factory=list)


class CommandEndpoint(Model):
    source: Literal["query", "form", "json"] = "query"
    field: str = "command"
    response: Literal["text", "json"] = "json"


class Contract(Model):
    id: str = Field(pattern=r"^[a-z][a-z0-9_-]*$")
    http: HTTPMatch | None = None
    command: CommandMatch | None = None
    mode: Literal["deterministic", "model"] = "deterministic"
    guidance: str = ""
    examples: list[str] = Field(default_factory=list)
    requires: dict[str, str] = Field(default_factory=dict)
    reply: Reply = Field(default_factory=Reply)
    error: Reply = Field(default_factory=lambda: Reply(status=400, body="Invalid request\n", exit_status=1))
    checks: Checks = Field(default_factory=Checks)
    fallback: Reply | None = None
    effects: Effects = Field(default_factory=Effects)
    endpoint: CommandEndpoint | None = None

    @model_validator(mode="after")
    def valid_contract(self) -> Contract:
        if (self.http is None) == (self.command is None):
            raise ValueError("A contract needs exactly one of http or command")
        if self.endpoint and (not self.http or self.mode != "deterministic"):
            raise ValueError("Command endpoints need a deterministic HTTP contract")
        return self


class Program(Model):
    name: str
    path: str
    aliases: list[str] = Field(default_factory=list)
    help: str | None = None
    version: str | None = None


class CommandEnvironment(Model):
    dialect: Literal["linux", "cmd", "powershell-5.1", "powershell-7"] = "linux"
    username: str = "guest"
    shell_version: str | None = Field(default=None, pattern=r'^[0-9]+(?:\.[0-9]+){0,3}$')
    ansi_encoding: Literal['cp1252', 'utf-8'] = 'cp1252'
    home: str | None = None
    directories: list[str] = Field(default_factory=list)
    environment: dict[str, str] = Field(default_factory=dict)
    programs: list[Program] = Field(default_factory=list)


class SSHAuthAccount(Model):
    shadow: Literal['*', '!', '$5$', '$6$']
    uid: int = Field(ge=0)
    shell: str = '/bin/ash'
    password: str | None = None

    @model_validator(mode='after')
    def valid_account(self) -> SSHAuthAccount:
        if not self.shell.startswith('/') or any(c in self.shell for c in '\r\n\x00'):
            raise ValueError('SSH account shell must be an absolute virtual path')
        if self.shadow in {'$5$', '$6$'} and not self.password:
            raise ValueError('A password account requires a nonempty fixture password')
        if self.shadow not in {'$5$', '$6$'} and self.password is not None:
            raise ValueError('Only password accounts may define a fixture password')
        return self


class SSHAuthPolicy(Model):
    kind: Literal['musl-star-bypass']
    accounts: dict[str, SSHAuthAccount] = Field(min_length=1)
    password_authentication: bool = True
    use_pam: bool = False
    patched: bool = False
    permit_root_login: Literal['yes', 'prohibit-password', 'no'] = 'prohibit-password'

    @model_validator(mode='after')
    def valid_accounts(self) -> SSHAuthPolicy:
        if any(not re.fullmatch(r'[a-z_][a-z0-9_-]*', name) for name in self.accounts):
            raise ValueError('SSH auth account names must be safe local usernames')
        return self


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


class DevicePack(Model):
    platform: Literal['linux', 'macos', 'freebsd', 'ios'] = 'linux'
    interpreter: Literal['bash', 'zsh', 'sh', 'ios'] = 'bash'
    home: str | None = None
    applications: list[Literal['less', 'top', 'vi', 'device-menu']] = Field(
        default_factory=lambda: ['less', 'top', 'vi', 'device-menu'])
    model_effects: bool = False
    enable_password: str = 'fixture-enable'

    @model_validator(mode='after')
    def valid_device(self) -> DevicePack:
        if (self.platform == 'ios') != (self.interpreter == 'ios'):
            raise ValueError('IOS devices require the IOS interpreter')
        if self.home and (not self.home.startswith('/') or '\x00' in self.home):
            raise ValueError('Device home must be a virtual absolute path')
        return self


class Profile(Model):
    _bound_base: Any = PrivateAttr(default=None)
    schema_version: Literal[1, 2] = 1
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
    fallback: Literal["reject", "llm", "llm_if_available"] = "reject"
    fallback_reply: Reply = Field(default_factory=lambda: Reply(body="Not found\n", status=404))
    stateful: bool = False
    cookie_name: str = "session"
    ssh_response_format: Literal["text", "json"] = "text"
    references: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    requirements: Requirements | None = None
    parameters: dict[str, Parameter] = Field(default_factory=dict)
    contracts: list[Contract] = Field(default_factory=list)
    command_environment: CommandEnvironment | None = None
    ssh_auth: SSHAuthPolicy | None = None
    device: DevicePack | None = None
    instance_id: str | None = None
    organization_id: str | None = None
    resolved_parameters: dict[str, Any] = Field(default_factory=dict)
    parameter_origins: dict[str, str] = Field(default_factory=dict)
    binding_fingerprint: str | None = None
    definition_fingerprint: str | None = None

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
        if self.device and self.protocol != 'ssh':
            raise ValueError('Device packs require SSH')
        if self.schema_version == 2 and not re.fullmatch(r'[a-z][a-z0-9_-]*', self.id):
            raise ValueError('Profile IDs must start with a lowercase letter and use letters, digits, underscores or hyphens')
        if self.schema_version == 1 and (self.parameters or self.contracts or self.command_environment
                                         or self.ssh_auth):
            raise ValueError("Parameters, contracts, command environments and SSH auth policies require schema_version: 2")
        if self.ssh_auth and self.protocol != 'ssh':
            raise ValueError('SSH auth policies require an SSH profile')
        if self.ssh_auth and '/etc/ssh/sshd_config' in self.files:
            config_text = self.files['/etc/ssh/sshd_config']
            expected = {
                'PasswordAuthentication': 'yes' if self.ssh_auth.password_authentication else 'no',
                'PermitRootLogin': self.ssh_auth.permit_root_login,
                'UsePAM': 'yes' if self.ssh_auth.use_pam else 'no',
            }
            for directive, value in expected.items():
                found = re.findall(rf'(?im)^\s*{directive}\s+(\S+)\s*$', config_text)
                if found and (len(found) != 1 or found[0].lower() != value):
                    raise ValueError(f'ssh_auth conflicts with virtual sshd_config {directive}')
        if len({c.id for c in self.contracts}) != len(self.contracts):
            raise ValueError("Contract IDs must be unique")
        if any(not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) for name in self.parameters):
            raise ValueError("Invalid parameter name")
        if self.protocol != "ssh" and (self.ssh_response_format != "text" or any(
            reply.stderr or reply.stderr_base64 is not None
            for reply in [self.fallback_reply] + [behavior.reply for behavior in self.behaviors]
        )):
            raise ValueError("SSH response format and stderr are only supported for SSH profiles")
        if len({b.id for b in self.behaviors}) != len(self.behaviors):
            raise ValueError("Behavior IDs must be unique")
        if not self.http_versions:
            raise ValueError("http_versions cannot be empty")
        if self.prompt and self.prompt_file:
            raise ValueError("Choose prompt or prompt_file, not both")
        if not self.cookie_name or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for c in self.cookie_name):
            raise ValueError("cookie_name must be an HTTP token")
        windows = self.command_environment and self.command_environment.dialect != "linux"
        if any(not (re.match(r"^[A-Za-z]:[\\/]", p) if windows else p.startswith("/")) for p in self.files):
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
    channel_limit: int = Field(default=16, ge=1, le=128)
    application_depth: int = Field(default=8, ge=1, le=32)
    screen_columns: int = Field(default=240, ge=20, le=500)
    screen_rows: int = Field(default=100, ge=5, le=200)
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
    api_key_env: str | None = Field(default=None, pattern=r'^[A-Za-z_][A-Za-z0-9_]*$')
    api_key_file: Path | None = None
    api_key: SecretStr | None = Field(default=None, exclude=True, repr=False)
    env_file: Path | None = None
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
        if self.api_key is not None and (self.api_key_env or self.api_key_file):
            raise ValueError('Choose a literal key or an environment/file reference')
        if self.kind == "bedrock" and (self.api_key_env or self.api_key_file or self.api_key):
            raise ValueError("Bedrock uses the AWS credential chain; mount AWS_SHARED_CREDENTIALS_FILE")
        if self.max_output_tokens + 256 >= self.context_tokens:
            raise ValueError("context_tokens must leave room for input and max_output_tokens")
        return self


class Listener(Model):
    name: str = "main"
    protocol: str = Field(min_length=1)
    profile: str | Selection | None = None
    profiles: list[str | Selection] = Field(default_factory=list)
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


class Deception(Selection):
    pass


class DeceptionDefaults(Model):
    host: str = "0.0.0.0"
    provider: str | None = None
    analyze: bool = False


class Deployment(Model):
    schema_version: Literal[1, 2] = 1
    organization: Path | None = None
    data_dir: Path = Path(".deceive")
    sensor_name: str = "deceive"
    log_file: Path | None = None
    limits: Limits = Field(default_factory=Limits)
    providers: dict[str, ProviderConfig] = Field(default_factory=dict)
    default_provider: str | None = None
    listeners: list[Listener] = Field(default_factory=list)
    deceptions: list[Deception] = Field(default_factory=list)
    deception_defaults: DeceptionDefaults = Field(default_factory=DeceptionDefaults)
    extensions: dict[str, list[str]] = Field(default_factory=dict)

    @model_validator(mode='before')
    @classmethod
    def inherit_default_provider(cls, value: Any) -> Any:
        if not isinstance(value, dict) or value.get('default_provider') is None:
            return value
        value = dict(value)
        default = value['default_provider']
        defaults = dict(value.get('deception_defaults') or {})
        defaults.setdefault('provider', default)
        value['deception_defaults'] = defaults
        listeners = []
        for listener in value.get('listeners', []):
            if isinstance(listener, dict):
                listener = dict(listener)
                listener.setdefault('provider', default)
            elif 'provider' not in listener.model_fields_set:
                listener = listener.model_copy(update={'provider': default})
            listeners.append(listener)
        value['listeners'] = listeners
        return value

    @model_validator(mode="after")
    def valid_deployment(self) -> Deployment:
        if self.default_provider and self.default_provider not in self.providers:
            raise ValueError(f"Unknown default provider '{self.default_provider}'")
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
