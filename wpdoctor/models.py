"""Structures de données partagées par les modules d'audit."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    OK = "ok"

    @property
    def weight(self) -> int:
        return {
            "critical": 40,
            "high": 20,
            "medium": 10,
            "low": 4,
            "info": 0,
            "ok": 0,
        }[self.value]


@dataclass
class Finding:
    """Un résultat d'audit unitaire."""
    check: str            # identifiant court, ex. "xmlrpc-open"
    title: str            # libellé lisible
    severity: Severity
    detail: str = ""      # explication de ce qui a été observé
    recommendation: str = ""  # que faire
    evidence: str = ""    # preuve (URL, header, extrait)
    category: str = ""    # security | performance | seo

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d


@dataclass
class Report:
    target: str
    generated_at: str
    findings: list = field(default_factory=list)
    meta: dict = field(default_factory=dict)

    def add(self, f: Finding) -> None:
        self.findings.append(f)

    def by_category(self, category: str) -> list:
        return [f for f in self.findings if f.category == category]

    @property
    def score(self) -> int:
        """Score sur 100 : 100 = aucun problème. Chaque finding retire du poids."""
        penalty = sum(f.severity.weight for f in self.findings)
        return max(0, 100 - penalty)

    @property
    def grade(self) -> str:
        s = self.score
        if s >= 90:
            return "A"
        if s >= 75:
            return "B"
        if s >= 60:
            return "C"
        if s >= 40:
            return "D"
        return "F"

    def counts(self) -> dict:
        c = {sev.value: 0 for sev in Severity}
        for f in self.findings:
            c[f.severity.value] += 1
        return c

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "generated_at": self.generated_at,
            "score": self.score,
            "grade": self.grade,
            "counts": self.counts(),
            "meta": self.meta,
            "findings": [f.to_dict() for f in self.findings],
        }
