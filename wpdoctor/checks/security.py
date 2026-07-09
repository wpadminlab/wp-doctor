"""Audit de sécurité d'un site WordPress (à distance, non intrusif).

Toutes les vérifications sont passives : on lit des ressources publiques.
Aucune tentative d'exploitation, aucun brute-force, aucune écriture.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin

from ..http import fetch
from ..models import Finding, Severity

CATEGORY = "security"

# Fichiers qui ne devraient jamais être servis publiquement.
SENSITIVE_PATHS = [
    (".env", Severity.CRITICAL, "Fichier d'environnement (secrets, clés API, mots de passe)"),
    ("wp-config.php.bak", Severity.CRITICAL, "Sauvegarde de wp-config.php (identifiants base de données)"),
    ("wp-config.php~", Severity.CRITICAL, "Sauvegarde d'éditeur de wp-config.php"),
    ("wp-config.php.save", Severity.CRITICAL, "Sauvegarde de wp-config.php"),
    (".wp-config.php.swp", Severity.HIGH, "Fichier swap Vim de wp-config.php"),
    ("wp-config.php.old", Severity.CRITICAL, "Ancienne version de wp-config.php"),
    ("debug.log", Severity.MEDIUM, "Journal de débogage WordPress (chemins, erreurs)"),
    ("wp-content/debug.log", Severity.MEDIUM, "Journal de débogage WordPress"),
    (".git/config", Severity.HIGH, "Dépôt Git exposé (code source, historique)"),
    (".htaccess.bak", Severity.MEDIUM, "Sauvegarde de configuration Apache"),
    ("wp-content/uploads/", Severity.LOW, "Listing du répertoire uploads potentiellement ouvert"),
    ("readme.html", Severity.LOW, "readme.html expose la version exacte de WordPress"),
    ("license.txt", Severity.INFO, "license.txt présent (empreinte WordPress)"),
    ("wp-content/backup-db/", Severity.HIGH, "Répertoire de sauvegarde BDD potentiellement accessible"),
    ("backup.sql", Severity.CRITICAL, "Dump SQL accessible publiquement"),
    ("wp-content/uploads/backup.zip", Severity.HIGH, "Archive de sauvegarde accessible"),
]

# En-têtes de sécurité recommandés.
SECURITY_HEADERS = [
    ("strict-transport-security", Severity.MEDIUM, "HSTS force le HTTPS et protège du downgrade",
     "Ajouter : Strict-Transport-Security: max-age=31536000; includeSubDomains"),
    ("content-security-policy", Severity.MEDIUM, "CSP limite les scripts exécutables (anti-XSS)",
     "Définir une Content-Security-Policy adaptée à votre thème"),
    ("x-frame-options", Severity.LOW, "X-Frame-Options protège du clickjacking",
     "Ajouter : X-Frame-Options: SAMEORIGIN"),
    ("x-content-type-options", Severity.LOW, "Empêche le MIME-sniffing",
     "Ajouter : X-Content-Type-Options: nosniff"),
    ("referrer-policy", Severity.LOW, "Contrôle les informations de referrer envoyées",
     "Ajouter : Referrer-Policy: strict-origin-when-cross-origin"),
    ("permissions-policy", Severity.INFO, "Restreint l'accès aux API du navigateur",
     "Envisager une Permissions-Policy"),
]


def _base(url: str) -> str:
    return url if url.endswith("/") else url + "/"


# Signatures de pages d'erreur/blocage servies parfois en HTTP 200 par les WAF.
_BLOCK_MARKERS = (
    "403 forbidden", "404 not found", "406 not acceptable", "access denied",
    "not acceptable", "forbidden", "mod_security", "request rejected",
    "page not found", "error 404", "error 403",
)


def _looks_blocked(body: str) -> bool:
    """Vrai si le corps ressemble à une page d'erreur/blocage (soft-403/404)."""
    head = body[:600].lower()
    return any(m in head for m in _BLOCK_MARKERS)


def _title(html: str) -> str:
    m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    return m.group(1).strip()[:120] if m else ""


# Fichiers dont le contenu réel n'est jamais du HTML. Si la réponse est une
# page HTML, c'est une redirection/fallback du WAF (faux positif).
_NON_HTML_FILES = (
    ".env", ".bak", ".swp", ".old", ".save", ".sql", ".log",
    ".git/config", ".htaccess.bak", "backup-db", "~",
)


def _is_html(body: str) -> bool:
    head = body.lstrip()[:200].lower()
    return head.startswith("<!doctype html") or head.startswith("<html") or "<head>" in head


def _is_waf_fallback(path: str, body: str, home_title: str) -> bool:
    """Détecte quand le serveur sert la home (ou une page HTML) à la place du fichier."""
    # 1. Même titre que la page d'accueil → c'est la home qui est servie.
    if home_title and _title(body) == home_title:
        return True
    # 2. Fichier censé ne pas être du HTML mais réponse HTML → fallback.
    if any(path.endswith(ext) or ext in path for ext in _NON_HTML_FILES) and _is_html(body):
        return True
    return False


def run(target: str, home_html: str = "", verify_tls: bool = True, quick: bool = False) -> list:
    findings: list = []
    base = _base(target)

    # 1. En-tête X-Powered-By / Server verbeux
    home = fetch(target, verify_tls=verify_tls)
    server = home.header("server")
    powered = home.header("x-powered-by")
    if powered:
        findings.append(Finding(
            check="header-x-powered-by", category=CATEGORY,
            title="En-tête X-Powered-By exposé",
            severity=Severity.LOW,
            detail=f"Le serveur révèle sa pile technique : {powered}",
            recommendation="Masquer X-Powered-By (expose_php = Off en PHP, ou header_remove).",
            evidence=f"X-Powered-By: {powered}",
        ))

    # 2. En-têtes de sécurité manquants
    for name, sev, why, reco in SECURITY_HEADERS:
        if not home.header(name):
            findings.append(Finding(
                check=f"missing-{name}", category=CATEGORY,
                title=f"En-tête de sécurité manquant : {name}",
                severity=sev, detail=why, recommendation=reco,
            ))

    # 3. Version de WordPress exposée (meta generator + readme)
    ver = None
    m = re.search(r'<meta name="generator" content="WordPress ([0-9.]+)"', home_html or home.body)
    if m:
        ver = m.group(1)
        findings.append(Finding(
            check="wp-version-generator", category=CATEGORY,
            title="Version de WordPress exposée (meta generator)",
            severity=Severity.LOW,
            detail=f"La balise generator révèle WordPress {ver}.",
            recommendation="Supprimer la balise generator via functions.php : remove_action('wp_head', 'wp_generator').",
            evidence=f'<meta name="generator" content="WordPress {ver}">',
        ))

    # 4. XML-RPC ouvert (surface d'attaque : brute-force, pingback DDoS)
    xmlrpc = fetch(urljoin(base, "xmlrpc.php"), method="POST", verify_tls=verify_tls)
    if xmlrpc.status == 405 or "XML-RPC server accepts POST requests only" in xmlrpc.body or "methodResponse" in xmlrpc.body:
        findings.append(Finding(
            check="xmlrpc-open", category=CATEGORY,
            title="xmlrpc.php accessible",
            severity=Severity.MEDIUM,
            detail="XML-RPC est actif : vecteur classique de brute-force (system.multicall) et d'amplification pingback.",
            recommendation="Bloquer xmlrpc.php si non utilisé (règle serveur ou filtre) ou restreindre les méthodes.",
            evidence=f"POST xmlrpc.php → HTTP {xmlrpc.status}",
        ))

    # 5. Énumération des utilisateurs via l'API REST
    users = fetch(urljoin(base, "wp-json/wp/v2/users"), verify_tls=verify_tls)
    if users.ok and users.body.strip().startswith("["):
        names = re.findall(r'"slug":"([^"]+)"', users.body)
        if names:
            findings.append(Finding(
                check="rest-user-enum", category=CATEGORY,
                title="Énumération des utilisateurs via l'API REST",
                severity=Severity.MEDIUM,
                detail=f"wp-json/wp/v2/users expose {len(names)} identifiant(s) : {', '.join(names[:5])}"
                       + ("…" if len(names) > 5 else ""),
                recommendation="Restreindre l'endpoint users de l'API REST (filtre rest_endpoints ou plugin de sécurité).",
                evidence=f"GET wp-json/wp/v2/users → {len(names)} slugs",
            ))

    # 6. Énumération via ?author=1
    author = fetch(urljoin(base, "?author=1"), verify_tls=verify_tls, allow_redirects=False)
    loc = author.header("location")
    if loc and "/author/" in loc:
        slug = loc.rstrip("/").split("/author/")[-1]
        findings.append(Finding(
            check="author-enum", category=CATEGORY,
            title="Énumération d'auteur via ?author=1",
            severity=Severity.LOW,
            detail=f"La redirection ?author=1 révèle un identifiant de connexion : « {slug} ».",
            recommendation="Bloquer les requêtes ?author= ou dissocier le login du slug public (nicename).",
            evidence=f"?author=1 → 301 {loc}",
        ))

    # 7. Fichiers sensibles
    home_title = _title(home_html or home.body)
    paths = SENSITIVE_PATHS if not quick else SENSITIVE_PATHS[:8]
    for path, sev, desc in paths:
        r = fetch(urljoin(base, path), verify_tls=verify_tls, max_bytes=4096)
        if r.status == 200:
            # Filtrer les faux positifs : page d'erreur/blocage servie en 200 (WAF)
            is_listing = path.endswith("/") and ("Index of" in r.body or "<title>Index of" in r.body)
            if path.endswith("/") and not is_listing:
                continue
            if _looks_blocked(r.body):
                continue
            if _is_waf_fallback(path, r.body, home_title):
                continue
            findings.append(Finding(
                check=f"exposed-{path.strip('/').replace('/', '-')}", category=CATEGORY,
                title=f"Ressource sensible accessible : {path}",
                severity=sev, detail=desc,
                recommendation=f"Bloquer l'accès public à {path} (règle serveur) ou le supprimer.",
                evidence=f"GET {path} → HTTP 200",
            ))

    # 8. wp-login.php sans limitation visible (info seulement — non intrusif)
    login = fetch(urljoin(base, "wp-login.php"), verify_tls=verify_tls, max_bytes=8192)
    if login.status == 200 and "user_login" in login.body:
        findings.append(Finding(
            check="wp-login-exposed", category=CATEGORY,
            title="wp-login.php accessible publiquement",
            severity=Severity.INFO,
            detail="La page de connexion est à l'URL par défaut. Ce n'est pas une faille en soi mais une cible de brute-force.",
            recommendation="Ajouter une limitation de tentatives (fail2ban, plugin) et idéalement un 2FA.",
            evidence="GET wp-login.php → HTTP 200",
        ))

    # 9. Répertoire wp-content/plugins listable
    plugins_dir = fetch(urljoin(base, "wp-content/plugins/"), verify_tls=verify_tls, max_bytes=8192)
    if plugins_dir.status == 200 and ("Index of" in plugins_dir.body):
        findings.append(Finding(
            check="plugins-listing", category=CATEGORY,
            title="Listing du répertoire des plugins ouvert",
            severity=Severity.MEDIUM,
            detail="wp-content/plugins/ liste les plugins installés : aide un attaquant à cibler des versions vulnérables.",
            recommendation="Désactiver l'indexation des répertoires (Options -Indexes) ou ajouter un index.php vide.",
            evidence="GET wp-content/plugins/ → Index of",
        ))

    return findings
