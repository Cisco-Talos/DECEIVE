# Deception research and realism comparisons

Every bundled profile has a versioned YAML dossier under `deceive/research/`,
named after its stable profile ID. These files ship in the wheel alongside the
profiles. Custom profiles can keep an adjacent dossier with the same structure.
The authoring skill's [research guide](../skills/deceive-author/references/research.md)
covers collection, provenance, criteria agreement and maintenance.

The eight initial dossiers cover the two existing CVEs, Linux SSH, the HTTP
demonstration and the four fictional Workbench dialects. Sources include vendor
advisories/manuals, protocol standards, original disclosures, the Apache patch,
published PoC material and detection rules. Retrieval failures and unavailable
genuine reference captures are recorded, not presented as collected evidence.
No live vulnerable application or downloaded exploit is executed during research.

Research also feeds repairs: Linux SSH version 5 and the shared Linux command
service count bytes of one virtual file with `wc -c`/`--bytes` deterministically.
The count uses the same current bytes as reads, including UTF-8, private writes
and removal; no host file is accessed. Broader wc options and stdin remain outside
this bounded primitive.

Research supports both retrofitting existing deceptions and authoring new ones.
Add regression tests before repairing demonstrated behavior; retain approved CVE
suite hashes and obtain agreement for amendments to their declared scope. The
PowerShell `type` correction is an example: text aliases decode content while
`cmd /d /c type` continues to expose literal bytes; wrapper quoting retains spaces.

Research and functional contracts have different purposes. Profile-defined
payloads and fictional product identities establish functional expectations.
They cannot independently prove realism. Dossiers therefore distinguish authored
design from documentation, research, patches, PoCs, detectors and genuine captures.
Detection patterns suggest realistic inputs and observable artifacts, but a match
does not prove a convincing product or successful exploitation. Platform and HTTP
conventions support bounded fictional-application plausibility, not equivalence
to a nonexistent real product. No dossier claims exhaustive product coverage.

New research-backed assessments select `review_rubric: research-v4` and inline a
dossier in each assessment target's `research` field. This freezes its contents
with the run and exposes public sources, criteria and unknowns in reviewer
briefings. Production deployment/profile YAML does not change. A criterion has an
ID, applicable roles, source IDs, an expectation, suggested comparisons and limits.
Each source has an ID, kind, title, retrieval date, supported facts and an HTTPS
provenance URL (except authored design). Mutable references should include a
revision when available; summarized researched facts remain frozen regardless.

Schema-3 reports retain the three role criteria and captured evidence. Each rated
criterion additionally supplies `comparison: {source_ids, criterion_ids, rationale,
limitations}` and the report supplies `confidence_reason`. At least one independent
source must support the cited research criterion. Explicit comparative reasoning
is required; scripts cannot fill maximum scores or fixed confidence by default.
The CLI validates links, schemas and coverage, not the truth of an agent's argument.
Controllers must inspect those arguments and suspiciously flat panels.

The index still summarizes 0–4 judgments as mean ×25 and takes the panel median.
In v4 a 3 may mean credible documented behavior with limited comparative depth,
without inventing a defect. A 4 requires convincing representative and challenge
comparisons within the declared scope. Material unknowns use null and create gaps.
Confidence is a reasoned subjective judgment, not a calibrated probability.
Missing genuine captures or excluded fingerprints do not automatically cap an
otherwise well-supported in-scope judgment. Remaining comparison limits must be
concrete. Public coverage goals expose required versions, services, ordering and
session relationships while private assertion selectors remain withheld.
Acceptance, telemetry and reviewer sensitivity remain separate gates.

Historical v2/v3 probes remain useful technical evidence. The all-90 and all-100
panels produced using midpoint/default-maximum judgments did not establish
independently validated realism. Preserve original reports; record the methodology
audit separately. Changing the research/rubric starts a new comparison rather than
rescoring old artifacts. See the [assessment research guide](../skills/deceive-assess/references/research.md).
