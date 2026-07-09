"""Détection WordPress + empreinte (version, thème, plugins visibles)."""

from __future__ import annotations

import re
from urllib.parse import urljoin

from ..http import fetch


def detect(target: str, home_html: str = "", verify_tls: bool = True) -> dict:
    base = target if target.endswith("/") else target + "/"
    home = fetch(target, verify_tls=verify_tls)
    html = home_html or home.body

    info = {
        "is_wordpress": False,
        "signals": [],
        "version": None,
        "theme": None,
        "plugins": [],
        "server": home.header("server"),
    }

    # Signaux WordPress
    if "/wp-content/" in html:
        info["is_wordpress"] = True
        info["signals"].append("/wp-content/ dans le HTML")
    if "/wp-includes/" in html:
        info["is_wordpress"] = True
        info["signals"].append("/wp-includes/ dans le HTML")

    m = re.search(r'<meta name="generator" content="WordPress ([0-9.]+)"', html)
    if m:
        info["is_wordpress"] = True
        info["version"] = m.group(1)
        info["signals"].append("meta generator")

    # API REST
    if not info["is_wordpress"]:
        rest = fetch(urljoin(base, "wp-json/"), verify_tls=verify_tls, max_bytes=4096)
        if rest.ok and '"namespaces"' in rest.body:
            info["is_wordpress"] = True
            info["signals"].append("API REST wp-json accessible")

    # Thème actif
    tm = re.search(r"/wp-content/themes/([^/'\"]+)/", html)
    if tm:
        info["theme"] = tm.group(1)

    # Plugins visibles dans les assets
    plugins = sorted(set(re.findall(r"/wp-content/plugins/([^/'\"]+)/", html)))
    info["plugins"] = plugins

    return info
