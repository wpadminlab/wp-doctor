"""Orchestration de l'audit : lance les modules et agrège un Report."""

from __future__ import annotations

import datetime
from urllib.parse import urlparse

from .http import fetch
from .models import Report
from .checks import security, performance, seo, detect


def normalize_url(raw: str) -> str:
    raw = raw.strip()
    if not raw.startswith(("http://", "https://")):
        raw = "https://" + raw
    p = urlparse(raw)
    # Retire un éventuel chemin pour repartir de la racine
    return f"{p.scheme}://{p.netloc}/"


def run_audit(
    raw_target: str,
    categories: list | None = None,
    verify_tls: bool = True,
    quick: bool = False,
) -> Report:
    target = normalize_url(raw_target)
    categories = categories or ["security", "performance", "seo"]

    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    report = Report(target=target, generated_at=now)

    # Une seule récupération de la home, réutilisée par tous les modules.
    home = fetch(target, verify_tls=verify_tls)
    if home.error or home.status == 0:
        report.meta["reachable"] = False
        report.meta["error"] = home.error or "injoignable"
        return report

    report.meta["reachable"] = True
    report.meta["status"] = home.status
    report.meta["final_ttfb_ms"] = round(home.elapsed_ms, 1)

    fingerprint = detect.detect(target, home_html=home.body, verify_tls=verify_tls)
    report.meta["wordpress"] = fingerprint

    if "security" in categories:
        report.findings += security.run(target, home_html=home.body, verify_tls=verify_tls, quick=quick)
    if "performance" in categories:
        report.findings += performance.run(target, home_html=home.body, verify_tls=verify_tls, quick=quick)
    if "seo" in categories:
        report.findings += seo.run(target, home_html=home.body, verify_tls=verify_tls, quick=quick)

    # Tri : par gravité décroissante puis par catégorie
    report.findings.sort(key=lambda f: (-f.severity.weight, f.category, f.check))
    return report
