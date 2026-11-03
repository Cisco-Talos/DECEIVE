from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator

from deceive.models import Model, ProviderConfig

Role = Literal["protocol", "product", "attacker", "consistency"]
ROLES = ("protocol", "product", "attacker", "consistency")
Slug = str


class Policy(Model):
    mode: Literal["until", "fixed"] = "until"
    max_loops: int = Field(default=20, ge=1, le=10000)
    minimum_realism: float = Field(default=85, ge=0, le=100)
    confirmations: int = Field(default=2, ge=1, le=20)
    plateau_cycles: int = Field(default=3, ge=1, le=20)
    minimum_gain: float = Field(default=3, gt=0, le=100)
    disagreement: float = Field(default=20, ge=0, le=100)


class ProbeLimits(Model):
    per_role_target: int = Field(default=30, ge=1, le=1000)
    reviewer_seconds: float = Field(default=600, gt=0, le=86400)
    concurrency: int = Field(default=4, ge=1, le=32)
    startup_seconds: float = Field(default=60, gt=0, le=600)
    build_seconds: float = Field(default=900, gt=0, le=7200)
    max_elapsed_seconds: float | None = Field(default=None, gt=0)


class DockerSettings(Model):
    image: str | None = None
    build: bool = True
    retain: bool = True
    provider_network: bool = False
    aws_dir: Path | None = None


class Target(Model):
    name: str = Field(pattern=r"^[a-z][a-z0-9_-]{0,127}$")
    profiles: list[str] = Field(default_factory=list)
    deployment: str | None = None
    protocol: str | None = None
    versions: list[Literal["1.1", "2", "3"]] | None = None
    suite: str | None = None
    provider: str | None = None
    claims: str = ""
    calibration: Literal["server_version"] | None = None

    @model_validator(mode="after")
    def source(self) -> Target:
        if bool(self.profiles) == bool(self.deployment):
            raise ValueError("Target needs profiles or a deployment, exclusively")
        return self


class Spec(Model):
    schema_version: Literal[1] = 1
    targets: list[Target] = Field(default_factory=list)
    all_profiles: bool = False
    policy: Policy = Field(default_factory=Policy)
    limits: ProbeLimits = Field(default_factory=ProbeLimits)
    docker: DockerSettings = Field(default_factory=DockerSettings)
    providers: dict[str, ProviderConfig] = Field(default_factory=dict)
    drivers: list[str] = Field(default_factory=list)
    roles: list[Role] = Field(default_factory=lambda: list(ROLES))
    review_rubric: Literal["legacy-v1", "evidence-v2"] = "evidence-v2"

    @model_validator(mode="after")
    def selected(self) -> Spec:
        if not self.targets and not self.all_profiles:
            raise ValueError("Select targets or all_profiles")
        if len({t.name for t in self.targets}) != len(self.targets):
            raise ValueError("Assessment target names must be unique")
        if not self.roles or len(set(self.roles)) != len(self.roles):
            raise ValueError("Required reviewer roles must be nonempty and unique")
        for target in self.targets:
            if target.provider and target.provider not in self.providers:
                raise ValueError(f"Unknown assessment target provider: {target.provider}")
        return self


class ProbeAction(Model):
    schema_version: Literal[1] = 1
    operation: str = Field(min_length=1, max_length=64)
    endpoint: str | None = None
    session: str | None = Field(default=None, pattern=r"^[a-zA-Z0-9_-]{1,64}$")
    parameters: dict = Field(default_factory=dict)


class Observation(Model):
    schema_version: Literal[1] = 1
    interaction_id: str
    target: str
    role: str
    candidate_id: str
    timestamp: str
    action: ProbeAction
    protocol: str
    version: str = ""
    session_id: str | None = None
    body_base64: str = ""
    headers: list[tuple[str, str]] = Field(default_factory=list)
    facts: dict = Field(default_factory=dict)
    error: str | None = None


class Finding(Model):
    schema_version: Literal[1] = 1
    id: str = Field(pattern=r"^[a-zA-Z0-9_-]{1,80}$")
    severity: Literal["P0", "P1", "P2", "P3", "P4"]
    category: Literal["protocol_contract", "vulnerability_semantics", "identity_or_state",
                      "composition", "response_format", "operational_tell",
                      "unproven_or_out_of_scope"]
    description: str = Field(min_length=1, max_length=10000)
    evidence: list[str] = Field(min_length=1, max_length=100)
    expected: str = Field(min_length=1, max_length=10000)
    reference: str | None = None
    proposed_owner: str = ""


class ScoreBasis(Model):
    band: Literal["no_material_tell", "minor_tell", "mixed", "major_contradiction", "direct_disclosure"]
    observations: list[str] = Field(min_length=1, max_length=30)
    evidence: list[str] = Field(min_length=1, max_length=100)
    coverage_limits: str = Field(min_length=1, max_length=6000)


class Review(Model):
    schema_version: Literal[1] = 1
    candidate_id: str
    role: Role
    target: str
    synthetic_confidence: float = Field(ge=0, le=100)
    verdict_confidence: float = Field(ge=0, le=100)
    summary: str = Field(min_length=1, max_length=20000)
    findings: list[Finding] = Field(default_factory=list, max_length=100)
    usage: dict[str, float] | None = None
    score_basis: ScoreBasis | None = None

    @model_validator(mode="after")
    def unique_findings(self) -> Review:
        if len({f.id for f in self.findings}) != len(self.findings):
            raise ValueError("Finding IDs must be unique within a review")
        if self.score_basis:
            from deceive.assessment.rubric import BANDS
            low, high, _ = BANDS[self.score_basis.band]
            if not (low <= self.synthetic_confidence <= high and
                    (low == 0 or self.synthetic_confidence > low)):
                raise ValueError("Synthetic confidence falls outside the selected evidence band")
            if self.score_basis.band != "no_material_tell" and not self.findings:
                raise ValueError("An observed-tell score band requires an evidence-backed finding")
        return self


class Decision(Model):
    status: Literal["verified", "false_positive", "unproven", "resolved"]
    rationale: str = Field(min_length=1)
    evidence: list[str] = Field(min_length=1)


class Decisions(Model):
    schema_version: Literal[1] = 1
    findings: dict[str, Decision] = Field(default_factory=dict)
    progress: list[str] = Field(default_factory=list)
    reconciliations: dict[str, str] = Field(default_factory=dict)


class CandidateManifest(Model):
    schema_version: Literal[1] = 1
    number: int = Field(ge=1)
    attempt: int = Field(ge=1)
    directory: str
    started: str
    source: dict
    candidate_id: str
    comparison_id: str
    definitions_id: str
    image: str | None = None
    targets: dict[str, dict]
    correctness: dict[str, dict]
    reviews: dict[str, str]
    broker: dict | None = None
    session_reset_on_resume: bool = False


class LoopResult(Model):
    schema_version: Literal[1] = 1
    loop: int = Field(ge=1)
    attempt: int = Field(ge=1)
    candidate_id: str
    comparison_id: str
    source: dict
    image: str | None
    client_id: str
    complete: bool
    qualified: bool
    targets: dict[str, dict]
    findings: list[dict]
    progress: list[str]
    plateau_confirmed: bool
    calibration_passed: bool
    started: str
    finished: str
    native_agent_usage: dict | None
    directory: str


class AssessmentRun(Model):
    schema_version: Literal[1] = 1
    run_id: str
    created: str
    started_epoch: float
    root: str
    spec: Spec
    baseline: dict
    phase: Literal["prepared", "active", "interrupted", "between_loops", "finished"]
    loops: list[LoopResult]
    current: CandidateManifest | None
    containers: dict[str, dict]
    stop_reason: str | None
    native_agent_usage: dict | None
    network: str | None = None
    teardown_errors: list[str] = Field(default_factory=list)
    policy_history: list[dict] = Field(default_factory=list)
    final_candidate_fresh: bool | None = None
    criteria: dict[str, str] = Field(default_factory=dict)
