"""Audit de performance (mesures HTTP simples, non intrusives)."""

from __future__ import annotations

import re
from urllib.parse import urljoin

from ..http import fetch
from ..models import Finding, Severity

CATEGORY = "performance"


def run(target: str, home_html: str = "", verify_tls: bool = True, quick: bool = False) -> list:
    findings: list = []
    home = fetch(target, verify_tls=verify_tls)
    html = home_html or home.body

    # 1. TTFB (approximé par le temps total de la requête home)
    ttfb = home.elapsed_ms
    if ttfb > 1500:
        sev = Severity.HIGH
    elif ttfb > 800:
        sev = Severity.MEDIUM
    elif ttfb > 400:
        sev = Severity.LOW
    else:
        sev = Severity.OK
    if sev != Severity.OK:
        findings.append(Finding(
            check="slow-ttfb", category=CATEGORY,
            title="Temps de réponse serveur élevé",
            severity=sev,
            detail=f"La page d'accueil a répondu en {ttfb:.0f} ms.",
            recommendation="Activer un cache de page (LiteSpeed/WP Rocket), optimiser PHP/BDD, envisager un CDN.",
            evidence=f"TTFB ≈ {ttfb:.0f} ms",
        ))

    # 2. Cache serveur détectable
    cache_headers = ["x-litespeed-cache", "x-cache", "cf-cache-status", "x-proxy-cache", "age"]
    has_cache = any(home.header(h) for h in cache_headers)
    if not has_cache:
        findings.append(Finding(
            check="no-page-cache", category=CATEGORY,
            title="Aucun cache de page détecté",
            severity=Severity.MEDIUM,
            detail="Aucun en-tête de cache (LiteSpeed, Cloudflare, Varnish…) n'a été observé.",
            recommendation="Installer un cache de page. Sur o2switch : plugin LiteSpeed Cache.",
            evidence="Aucun en-tête de cache dans la réponse",
        ))

    # 3. Compression
    if "gzip" not in home.header("content-encoding") and "br" not in home.header("content-encoding"):
        findings.append(Finding(
            check="no-compression", category=CATEGORY,
            title="Compression HTTP absente",
            severity=Severity.MEDIUM,
            detail="La réponse n'est ni gzip ni brotli : transfert plus lourd que nécessaire.",
            recommendation="Activer gzip/brotli (mod_deflate / configuration serveur).",
            evidence=f"Content-Encoding: {home.header('content-encoding') or '(vide)'}",
        ))

    # 4. Taille du HTML
    html_kb = len(home.body.encode("utf-8")) / 1024
    if html_kb > 150:
        findings.append(Finding(
            check="large-html", category=CATEGORY,
            title="Document HTML volumineux",
            severity=Severity.LOW,
            detail=f"Le HTML de la page fait {html_kb:.0f} Ko (hors images/CSS/JS).",
            recommendation="Réduire le HTML : moins de contenu inline, pas de CSS/JS massif dans la page.",
            evidence=f"HTML ≈ {html_kb:.0f} Ko",
        ))

    # 5. Images sans lazy-loading
    imgs = re.findall(r"<img\b[^>]*>", html, re.IGNORECASE)
    if imgs:
        no_lazy = [t for t in imgs if 'loading=' not in t.lower()]
        if len(no_lazy) > 3 and len(no_lazy) / max(1, len(imgs)) > 0.5:
            findings.append(Finding(
                check="no-lazy-images", category=CATEGORY,
                title="Images sans lazy-loading",
                severity=Severity.LOW,
                detail=f"{len(no_lazy)}/{len(imgs)} balises <img> n'ont pas d'attribut loading=\"lazy\".",
                recommendation="Ajouter loading=\"lazy\" aux images sous la ligne de flottaison.",
                evidence=f"{len(no_lazy)} images sans loading=lazy",
            ))

    # 6. Nombre de scripts/styles chargés (approximation des requêtes bloquantes)
    scripts = len(re.findall(r"<script\b[^>]*\bsrc=", html, re.IGNORECASE))
    styles = len(re.findall(r'<link\b[^>]*\brel=["\']?stylesheet', html, re.IGNORECASE))
    if scripts + styles > 25:
        findings.append(Finding(
            check="many-assets", category=CATEGORY,
            title="Nombreuses ressources externes",
            severity=Severity.LOW,
            detail=f"{scripts} script(s) et {styles} feuille(s) de style référencés dans la page.",
            recommendation="Concaténer/minifier, différer le JS non critique, retirer les plugins superflus.",
            evidence=f"{scripts} JS + {styles} CSS",
        ))

    # 7. Emoji WordPress inutile (wp-emoji-release)
    if "wp-emoji-release" in html:
        findings.append(Finding(
            check="wp-emoji", category=CATEGORY,
            title="Script emoji WordPress chargé",
            severity=Severity.INFO,
            detail="wp-emoji-release.min.js est chargé : rarement utile, ralentit légèrement.",
            recommendation="Désactiver via functions.php (remove_action wp_print_styles print_emoji_styles, etc.).",
            evidence="wp-emoji-release détecté",
        ))

    return findings
