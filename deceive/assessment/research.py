"""Portable research provenance; never imported by the production runtime."""
from __future__ import annotations

from datetime import date
from typing import Literal

from pydantic import Field, model_validator

from deceive.models import Model


class Source(Model):
    id: str = Field(pattern=r'^[a-z][a-z0-9_-]{0,79}$')
    kind: Literal['standard', 'vendor', 'disclosure', 'patch', 'poc', 'detection',
                  'reference_capture', 'design']
    title: str = Field(min_length=1)
    url: str | None = None
    retrieved: date
    revision: str | None = None
    facts: list[str] = Field(min_length=1)
    limitations: list[str] = Field(default_factory=list)

    @model_validator(mode='after')
    def provenance(self) -> Source:
        if self.kind != 'design' and (not self.url or not self.url.startswith('https://')):
            raise ValueError('Independent research sources require an HTTPS provenance URL')
        return self


class RealismCriterion(Model):
    id: str = Field(pattern=r'^[a-z][a-z0-9_-]{0,79}$')
    roles: list[Literal['protocol', 'product', 'attacker', 'consistency']] = Field(min_length=1)
    sources: list[str] = Field(min_length=1)
    expectation: str = Field(min_length=1)
    comparisons: list[str] = Field(min_length=1)
    limitations: list[str] = Field(default_factory=list)


class Dossier(Model):
    schema_version: Literal[1] = 1
    profile_id: str = Field(pattern=r'^[a-z][a-z0-9_-]{0,127}$')
    version: str
    subject: str = Field(min_length=1)
    kind: Literal['real_product', 'fictional']
    sources: list[Source] = Field(min_length=1)
    criteria: list[RealismCriterion] = Field(min_length=1)
    unknowns: list[str] = Field(default_factory=list)
    search_notes: list[str] = Field(default_factory=list)

    @model_validator(mode='after')
    def links(self) -> Dossier:
        sources = {s.id for s in self.sources}
        if len(sources) != len(self.sources) or len({c.id for c in self.criteria}) != len(self.criteria):
            raise ValueError('Research source and criterion IDs must be unique')
        for criterion in self.criteria:
            if not set(criterion.sources).issubset(sources):
                raise ValueError('Research criterion cites an unknown source')
        return self


class Comparison(Model):
    source_ids: list[str] = Field(min_length=1)
    criterion_ids: list[str] = Field(min_length=1)
    rationale: str = Field(min_length=40, max_length=6000)
    limitations: str = Field(min_length=10, max_length=6000)


def comparison_errors(dossier: Dossier | None, report: dict) -> list[str]:
    if dossier is None:
        return ['Missing frozen research dossier']
    sources = {s.id: s for s in dossier.sources}
    criteria = {c.id: c for c in dossier.criteria}
    errors = []
    for name, rating in report.get('ratings', {}).items():
        if rating.get('rating') is None:
            continue
        comparison = rating.get('comparison') or {}
        selected = set(comparison.get('source_ids', []))
        linked = set(comparison.get('criterion_ids', []))
        if not selected or not selected.issubset(sources):
            errors.append(f'{name}: missing or unknown research source')
        elif not any(sources[s].kind != 'design' for s in selected):
            errors.append(f'{name}: independent comparison evidence required; design is conformance')
        if not linked or not linked.issubset(criteria):
            errors.append(f'{name}: missing or unknown realism criterion')
        elif any(report['role'] not in criteria[c].roles for c in linked):
            errors.append(f'{name}: realism criterion belongs to another role')
        elif not selected.issubset({s for c in linked for s in criteria[c].sources}):
            errors.append(f'{name}: research sources do not support the cited realism criteria')
    return errors
