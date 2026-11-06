# Research a deception before implementing it

Create a versioned dossier beside the profile and acceptance assets. Bundled
profiles use `deceive/research/PROFILE_ID.yaml`; custom profiles may use an adjacent
research directory. Keep it portable, credential-free and keyed to the stable
profile ID. Research applies to fictional applications too: research their
protocol/platform conventions, and label invented application behavior as design.
Outside a checkout, bundled dossiers are package resources available through
`importlib.resources.files('deceive').joinpath('research')`.

Record sources with stable IDs, URLs, titles, retrieval dates, versions/commit IDs
when available, concise supported facts and limitations. Prefer vendor manuals,
advisories, patches and original disclosures. Inspect relevant PoCs and published
detection rules as text. Record search scope and unsuccessful retrievals honestly;
do not turn an unverified URL into evidence. Never execute downloaded exploits or
start vulnerable reference services as part of research.

Cover ordinary behavior as well as exploitation: discovery, identity/version,
normal requests/commands, output formatting and encoding, errors, prerequisites,
unsuccessful attempts, variations, follow-up effects and state. Explain differences
between versions, configurations, platforms and access policies. A PoC demonstrates
one workflow; a detector's signatures are neither the complete product behavior
nor proof that exploitation succeeded. Separate request visibility from host-only
artifacts the honeypot does not expose. Do not copy entire copyrighted sources.

Keep three evidence classes explicit:

- Independent documentation/research, with the exact claim it supports.
- Genuine reference captures, with provenance, environment, collection method and
  hashes. Never relabel DECEIVE output or invented examples as reference captures.
- Authored design facts, including contracts and fictional identities. These
  establish functional expectations, not independent evidence of realism.

Derive source-linked realism criteria separately from deterministic acceptance.
Each criterion identifies its observable expectation, applicable reviewer roles,
positive/challenge/follow-up comparisons, configuration dependencies and material
unknowns. For fictional products assess plausibility of protocol/platform behavior;
do not claim equivalence to a nonexistent real application. Completeness is bounded
to the declared surface; excluded functionality is not automatically a defect.

Propose behavior and functional/realism criteria for human agreement. Existing
approved CVE suites remain frozen: research can reveal a limitation or justify a
proposed amendment, but cannot silently change agreed behavior. Write independent
tests first for new vulnerability behavior and record the meaningful failing run.

Handoff to deceive-assess includes profile/version, dossier, acceptance agreement,
scope, unknowns and reproducible comparison suggestions. Freeze the dossier and
assessment definition for a run; new evidence changing criteria starts a new
comparison. Research is maintained evidence, not an assertion of exhaustive truth.
