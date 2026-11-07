from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import Field, SerializerFunctionWrapHandler, model_serializer, model_validator

from deceive.models import Model, ProviderConfig
from deceive.assessment.research import Comparison, Dossier

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
    minimum_dimension: float = Field(default=75, ge=0, le=100)
    minimum_verdict_confidence: float = Field(default=60, ge=0, le=100)


class EvidenceRule(Model):
    field: str = Field(min_length=1, max_length=256)
    exists: bool | None = None
    equals: object = None
    contains: str | None = None
    pattern: str | None = Field(default=None, max_length=1024)
    capture: str | None = None
    equals_capture: str | None = None
    not_equals_capture: str | None = None
    normalize: Literal['casefold', 'windows_path'] | None = None

    @model_validator(mode='after')
    def assertion(self) -> EvidenceRule:
        if 'equals' not in self.model_fields_set and all(getattr(self, key) is None for key in (
            'exists', 'contains', 'pattern', 'capture', 'equals_capture', 'not_equals_capture')):
            raise ValueError('Evidence rules need an assertion or capture')
        if self.exists is False and ('equals' in self.model_fields_set or any(
            getattr(self, key) is not None for key in ('contains', 'pattern', 'capture',
                                                      'equals_capture', 'not_equals_capture'))):
            raise ValueError('Absence rules cannot constrain or capture a missing value')
        if self.pattern:
            import regex
            try:
                regex.compile(self.pattern)
            except regex.error as exc:
                raise ValueError('Invalid evidence pattern') from exc
        return self

    @model_serializer(mode='wrap')
    def serialize(self, handler: SerializerFunctionWrapHandler) -> dict:
        # An omitted equality constraint must not become equals:null in frozen YAML/JSON.
        return {key: value for key, value in handler(self).items() if value is not None or
                (key == 'equals' and 'equals' in self.model_fields_set)}


class EvidenceStep(Model):
    select: list[EvidenceRule] = Field(min_length=1, max_length=20)
    expect: list[EvidenceRule] = Field(default_factory=list, max_length=20)


class CoverageGoal(Model):
    id: str = Field(pattern=r'^[a-z][a-z0-9_-]{0,79}$')
    role: Role
    criterion: str
    kind: Literal['baseline', 'positive', 'negative', 'variation', 'repeat', 'state', 'isolation']
    description: str = Field(min_length=1, max_length=3000)
    steps: list[EvidenceStep] = Field(min_length=1, max_length=12)
    every_service: bool = True
    every_version: bool = False
    same_session: bool = False
    different_sessions: bool = False
    ordered: bool = True

    @model_validator(mode='after')
    def coherent(self) -> CoverageGoal:
        from deceive.assessment.rubric import CRITERIA
        if self.criterion not in CRITERIA[self.role]:
            raise ValueError('Coverage criterion does not belong to its reviewer role')
        if self.same_session and self.different_sessions:
            raise ValueError('Choose same_session or different_sessions')
        if self.kind in {'repeat', 'state', 'isolation'} and len(self.steps) < 2:
            raise ValueError('Sequence coverage needs at least two interactions')
        if not self.ordered and self.kind in {'state', 'isolation'}:
            raise ValueError('State and isolation workflows must preserve operation order')
        return self


class CalibrationDefect(Model):
    id: str = Field(pattern=r'^[a-z][a-z0-9_-]{0,79}$')
    difficulty: Literal['major', 'subtle']
    description: str = Field(min_length=1)
    categories: list[str] = Field(min_length=1)
    observed: list[EvidenceRule] = Field(min_length=1)


class CalibrationControl(Model):
    defects: list[CalibrationDefect] = Field(min_length=1)


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
    control: CalibrationControl | None = None
    coverage: list[CoverageGoal] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    research: Dossier | None = None

    @model_validator(mode="after")
    def source(self) -> Target:
        if bool(self.profiles) == bool(self.deployment):
            raise ValueError("Target needs profiles or a deployment, exclusively")
        if len({g.id for g in self.coverage}) != len(self.coverage):
            raise ValueError('Coverage goal IDs must be unique per target')
        if self.control and len({d.id for d in self.control.defects}) != len(self.control.defects):
            raise ValueError('Control defect IDs must be unique')
        return self


class Spec(Model):
    schema_version: Literal[1, 2] = 2
    targets: list[Target] = Field(default_factory=list)
    all_profiles: bool = False
    policy: Policy = Field(default_factory=Policy)
    limits: ProbeLimits = Field(default_factory=ProbeLimits)
    docker: DockerSettings = Field(default_factory=DockerSettings)
    providers: dict[str, ProviderConfig] = Field(default_factory=dict)
    default_provider: str | None = None
    drivers: list[str] = Field(default_factory=list)
    roles: list[Role] = Field(default_factory=lambda: list(ROLES))
    review_rubric: Literal["legacy-v1", "evidence-v2", 'evidence-v3', 'research-v4'] = 'research-v4'
    require_live_model: bool = False

    @model_validator(mode="after")
    def selected(self) -> Spec:
        if self.require_live_model and (self.all_profiles or not self.providers or not self.docker.provider_network
                or any(not target.provider for target in self.targets)):
            raise ValueError('Online realism requires explicit targets, providers and provider_network')
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


class ProbePlan(Model):
    schema_version: Literal[1] = 1
    candidate_id: str
    role: Role
    target: str
    reserve_actions: int = Field(default=10, ge=1, le=1000)
    actions: list[ProbeAction] = Field(min_length=1, max_length=1000)


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
    instance_ids: list[str] = Field(default_factory=list)


class ScoreBasis(Model):
    band: Literal["no_material_tell", "minor_tell", "mixed", "major_contradiction", "direct_disclosure"]
    observations: list[str] = Field(min_length=1, max_length=30)
    evidence: list[str] = Field(min_length=1, max_length=100)
    coverage_limits: str = Field(min_length=1, max_length=6000)


class CriterionReview(Model):
    rating: Literal[0, 1, 2, 3, 4] | None
    expected: str = Field(min_length=1, max_length=6000)
    observed: str = Field(min_length=1, max_length=6000)
    reference: str = Field(min_length=1, max_length=2000)
    evidence: list[str] = Field(default_factory=list, max_length=100)
    coverage: list[str] = Field(default_factory=list, max_length=100)
    comparison: Comparison | None = None


class Review(Model):
    schema_version: Literal[1, 2, 3] = 1
    candidate_id: str
    role: Role
    target: str
    synthetic_confidence: float | None = Field(default=None, ge=0, le=100)
    verdict_confidence: float = Field(ge=0, le=100)
    confidence_reason: str | None = Field(default=None, min_length=20, max_length=6000)
    summary: str = Field(min_length=1, max_length=20000)
    findings: list[Finding] = Field(default_factory=list, max_length=100)
    usage: dict[str, float] | None = None
    score_basis: ScoreBasis | None = None
    ratings: dict[str, CriterionReview] = Field(default_factory=dict)

    @model_validator(mode="after")
    def unique_findings(self) -> Review:
        from deceive.assessment.rubric import CRITERIA
        if self.schema_version == 1:
            if self.synthetic_confidence is None or self.ratings:
                raise ValueError('Legacy reviews require synthetic_confidence and no v3 ratings')
        else:
            if self.schema_version == 3 and not self.confidence_reason:
                raise ValueError('Research reviews require a reason for verdict confidence')
            if self.synthetic_confidence is not None or self.score_basis is not None:
                raise ValueError('V3 reviews use criterion ratings, not synthetic confidence/bands')
            if set(self.ratings) - set(CRITERIA[self.role]):
                raise ValueError('Unknown criterion for reviewer role')
            for criterion in self.ratings.values():
                if self.schema_version == 3 and criterion.rating is not None and criterion.comparison is None:
                    raise ValueError('Research ratings require an individually justified comparison')
                if criterion.rating is not None and len(set(criterion.evidence)) < 2:
                    raise ValueError('Assessed criteria need two distinct interactions')
                if criterion.rating is not None and criterion.rating < (3 if self.schema_version == 3 else 4) and not any(
                    set(f.evidence).intersection(criterion.evidence) for f in self.findings
                ):
                    raise ValueError('A fidelity gap rating requires an evidence-backed finding; use null for uncertainty')
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
    review_rubric: str = 'legacy-v1'
    calibration_results: dict = Field(default_factory=dict)
    assessment_status: Literal['assessed', 'insufficiently_assessed', 'legacy_unvalidated'] = 'legacy_unvalidated'
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
    assessment_definition_id: str | None = None
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
