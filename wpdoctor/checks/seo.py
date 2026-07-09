"""Audit SEO technique (on-page + signaux crawl)."""

from __future__ import annotations

import re
from urllib.parse import urljoin

from ..http import fetch
from ..models import Finding, Severity

CATEGORY = "seo"


def _find(pattern: str, html: str, flags=re.IGNORECASE) -> str:
    m = re.search(pattern, html, flags)
    return m.group(1).strip() if m else ""


def _disallows_all(robots_body: str) -> bool:
    """Vrai seulement si le bloc « User-agent: * » contient « Disallow: / ».

    Un « Disallow: / » sous un autre user-agent (blocage de bots indésirables)
    ne bloque pas l'indexation générale et ne doit pas être signalé.
    """
    group_agents: list = []
    seen_directive = False
    star_active = False
    for raw in robots_body.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        low = line.lower()
        if low.startswith("user-agent:"):
            # Un User-agent qui suit une directive démarre un nouveau groupe.
            if seen_directive:
                group_agents = []
                seen_directive = False
            group_agents.append(line.split(":", 1)[1].strip())
            star_active = any(a == "*" for a in group_agents)
        elif low.startswith("disallow:"):
            seen_directive = True
            if star_active and line.split(":", 1)[1].strip() == "/":
                return True
        elif low.startswith(("allow:", "crawl-delay:", "noindex:")):
            seen_directive = True
    return False


def run(target: str, home_html: str = "", verify_tls: bool = True, quick: bool = False) -> list:
    findings: list = []
    base = target if target.endswith("/") else target + "/"
    home = fetch(target, verify_tls=verify_tls)
    html = home_html or home.body

    # 1. Balise title
    title = _find(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    if not title:
        findings.append(Finding(
            check="missing-title", category=CATEGORY,
            title="Balise <title> absente",
            severity=Severity.HIGH,
            detail="Aucune balise title détectée sur la page d'accueil.",
            recommendation="Définir un title unique et descriptif (50-60 caractères).",
        ))
    elif len(title) > 65:
        findings.append(Finding(
            check="long-title", category=CATEGORY,
            title="Balise <title> trop longue",
            severity=Severity.LOW,
            detail=f"Le title fait {len(title)} caractères (risque de troncature en SERP).",
            recommendation="Viser 50-60 caractères.",
            evidence=title[:80],
        ))

    # 2. Meta description
    desc = _find(r'<meta[^>]*name=["\']description["\'][^>]*content=["\']([^"\']*)["\']', html)
    if not desc:
        desc = _find(r'<meta[^>]*content=["\']([^"\']*)["\'][^>]*name=["\']description["\']', html)
    if not desc:
        findings.append(Finding(
            check="missing-meta-desc", category=CATEGORY,
            title="Meta description absente",
            severity=Severity.MEDIUM,
            detail="Aucune meta description sur la page d'accueil.",
            recommendation="Ajouter une meta description de 140-160 caractères par page (Yoast/Rank Math).",
        ))
    elif len(desc) > 165:
        findings.append(Finding(
            check="long-meta-desc", category=CATEGORY,
            title="Meta description trop longue",
            severity=Severity.LOW,
            detail=f"La description fait {len(desc)} caractères (troncature probable).",
            recommendation="Viser 140-160 caractères.",
            evidence=desc[:100],
        ))

    # 3. Canonical
    canonical = _find(r'<link[^>]*rel=["\']canonical["\'][^>]*href=["\']([^"\']*)["\']', html)
    if not canonical:
        findings.append(Finding(
            check="missing-canonical", category=CATEGORY,
            title="URL canonique absente",
            severity=Severity.LOW,
            detail="Aucune balise rel=canonical sur la page d'accueil.",
            recommendation="Ajouter une canonical par page (géré par Yoast/Rank Math).",
        ))

    # 4. Open Graph
    og = re.findall(r'<meta[^>]*property=["\']og:', html)
    if len(og) < 2:
        findings.append(Finding(
            check="missing-og", category=CATEGORY,
            title="Balises Open Graph absentes ou incomplètes",
            severity=Severity.LOW,
            detail="Peu ou pas de balises og: — le partage sur réseaux sociaux sera dégradé.",
            recommendation="Ajouter og:title, og:description, og:image, og:type (Yoast/Rank Math le fait).",
        ))

    # 5. Données structurées (schema.org)
    has_jsonld = "application/ld+json" in html
    has_microdata = "itemscope" in html or "itemtype" in html
    if not has_jsonld and not has_microdata:
        findings.append(Finding(
            check="no-structured-data", category=CATEGORY,
            title="Aucune donnée structurée détectée",
            severity=Severity.MEDIUM,
            detail="Ni JSON-LD ni microdata : pas de rich snippets possibles, moins de contexte pour les moteurs IA.",
            recommendation="Ajouter du schema.org JSON-LD (Article, Organization, BreadcrumbList, FAQPage).",
        ))

    # 6. Balise H1
    h1s = re.findall(r"<h1\b[^>]*>(.*?)</h1>", html, re.IGNORECASE | re.DOTALL)
    if len(h1s) == 0:
        findings.append(Finding(
            check="no-h1", category=CATEGORY,
            title="Aucun H1 sur la page d'accueil",
            severity=Severity.LOW,
            detail="Pas de titre H1 détecté.",
            recommendation="Un H1 unique et descriptif par page.",
        ))
    elif len(h1s) > 1:
        findings.append(Finding(
            check="multiple-h1", category=CATEGORY,
            title="Plusieurs H1 sur la page",
            severity=Severity.INFO,
            detail=f"{len(h1s)} balises H1 détectées.",
            recommendation="Privilégier un seul H1 par page pour une hiérarchie claire.",
        ))

    # 7. Attribut lang
    lang = _find(r'<html[^>]*\blang=["\']([^"\']+)["\']', html)
    if not lang:
        findings.append(Finding(
            check="no-lang", category=CATEGORY,
            title="Attribut lang absent sur <html>",
            severity=Severity.LOW,
            detail="La langue du document n'est pas déclarée.",
            recommendation="Ajouter lang=\"fr\" (ou la langue du site) sur la balise html.",
        ))

    # 8. robots.txt
    robots = fetch(urljoin(base, "robots.txt"), verify_tls=verify_tls, max_bytes=8192)
    if robots.status != 200:
        findings.append(Finding(
            check="no-robots", category=CATEGORY,
            title="robots.txt absent",
            severity=Severity.LOW,
            detail="Aucun robots.txt accessible.",
            recommendation="Fournir un robots.txt avec la directive Sitemap.",
            evidence=f"GET robots.txt → HTTP {robots.status}",
        ))
    else:
        if "sitemap" not in robots.body.lower():
            findings.append(Finding(
                check="robots-no-sitemap", category=CATEGORY,
                title="robots.txt sans référence au sitemap",
                severity=Severity.LOW,
                detail="robots.txt ne mentionne aucun Sitemap:.",
                recommendation="Ajouter « Sitemap: https://.../sitemap.xml » dans robots.txt.",
            ))
        if _disallows_all(robots.body):
            findings.append(Finding(
                check="robots-disallow-all", category=CATEGORY,
                title="robots.txt bloque tout le site",
                severity=Severity.CRITICAL,
                detail="Le bloc « User-agent: * » contient « Disallow: / » : l'ensemble du site est bloqué à l'indexation.",
                recommendation="Vérifier d'urgence : retirer le Disallow: / du bloc User-agent: * si le site doit être indexé.",
                evidence="User-agent: * → Disallow: /",
            ))

    # 9. Sitemap
    sitemap = fetch(urljoin(base, "sitemap.xml"), verify_tls=verify_tls, max_bytes=16384)
    sitemap_index = fetch(urljoin(base, "sitemap_index.xml"), verify_tls=verify_tls, max_bytes=16384) if sitemap.status != 200 else None
    if sitemap.status != 200 and (sitemap_index is None or sitemap_index.status != 200):
        findings.append(Finding(
            check="no-sitemap", category=CATEGORY,
            title="Sitemap XML introuvable",
            severity=Severity.MEDIUM,
            detail="Ni sitemap.xml ni sitemap_index.xml n'ont répondu en 200.",
            recommendation="Générer un sitemap (WordPress natif, Yoast, Rank Math) et le soumettre à la Search Console.",
        ))

    # 10. Noindex accidentel sur la home
    if re.search(r'<meta[^>]*name=["\']robots["\'][^>]*content=["\'][^"\']*noindex', html, re.IGNORECASE):
        findings.append(Finding(
            check="home-noindex", category=CATEGORY,
            title="Page d'accueil en noindex",
            severity=Severity.CRITICAL,
            detail="La balise meta robots contient « noindex » : la page ne sera pas indexée.",
            recommendation="Retirer le noindex si la page doit apparaître dans Google.",
        ))

    # 11. HTTPS / redirection
    if target.startswith("http://"):
        https_url = "https://" + target[len("http://"):]
        r = fetch(https_url, verify_tls=verify_tls, allow_redirects=False)
        if r.status == 0:
            findings.append(Finding(
                check="no-https", category=CATEGORY,
                title="HTTPS indisponible",
                severity=Severity.HIGH,
                detail="La version HTTPS du site ne répond pas.",
                recommendation="Installer un certificat TLS (Let's Encrypt) et forcer la redirection.",
            ))

    return findings
