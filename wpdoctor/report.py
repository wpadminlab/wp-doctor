"""Rendu des rapports : terminal coloré, Markdown, HTML, JSON."""

from __future__ import annotations

import json
import html as html_mod

from .models import Report, Severity


# --- Terminal ---------------------------------------------------------------

_ANSI = {
    "critical": "\033[97;41m",  # blanc sur rouge
    "high": "\033[91m",
    "medium": "\033[93m",
    "low": "\033[96m",
    "info": "\033[90m",
    "ok": "\033[92m",
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
}

_LABEL = {
    "critical": "CRITIQUE",
    "high": "ÉLEVÉ",
    "medium": "MOYEN",
    "low": "FAIBLE",
    "info": "INFO",
    "ok": "OK",
}

_CAT_LABEL = {
    "security": "🔒 Sécurité",
    "performance": "⚡ Performance",
    "seo": "🔍 SEO technique",
}


def _c(text: str, key: str, use_color: bool) -> str:
    if not use_color:
        return text
    return f"{_ANSI[key]}{text}{_ANSI['reset']}"


def render_terminal(report: Report, use_color: bool = True) -> str:
    lines = []
    b = lambda t: _c(t, "bold", use_color)

    lines.append("")
    lines.append(b(f"  wp-doctor — audit de {report.target}"))
    lines.append(_c(f"  {report.generated_at}", "dim", use_color))
    lines.append("")

    if not report.meta.get("reachable", False):
        lines.append(_c(f"  ✗ Site injoignable : {report.meta.get('error', 'inconnu')}", "high", use_color))
        return "\n".join(lines)

    wp = report.meta.get("wordpress", {})
    if wp.get("is_wordpress"):
        v = wp.get("version") or "version masquée"
        theme = wp.get("theme") or "?"
        lines.append(f"  WordPress détecté — {v} · thème : {theme}")
        if wp.get("plugins"):
            lines.append(_c(f"  Plugins visibles : {', '.join(wp['plugins'][:8])}", "dim", use_color))
    else:
        lines.append(_c("  WordPress non détecté (l'audit générique reste valable).", "dim", use_color))
    lines.append("")

    # Score
    grade_key = {"A": "ok", "B": "ok", "C": "medium", "D": "high", "F": "critical"}[report.grade]
    score_line = f"  Score : {report.score}/100   Note : {report.grade}"
    lines.append("  " + _c(f" {score_line.strip()} ", grade_key, use_color))
    counts = report.counts()
    summary = "  ".join(
        _c(f"{_LABEL[s]}: {counts[s]}", s, use_color)
        for s in ["critical", "high", "medium", "low", "info"]
        if counts[s]
    )
    if summary:
        lines.append("  " + summary)
    lines.append("")

    # Findings par catégorie
    for cat in ["security", "performance", "seo"]:
        items = report.by_category(cat)
        if not items:
            continue
        lines.append(b(f"  {_CAT_LABEL.get(cat, cat)}  ({len(items)})"))
        lines.append(_c("  " + "─" * 50, "dim", use_color))
        for f in items:
            badge = _c(f" {_LABEL[f.severity.value]} ", f.severity.value, use_color)
            lines.append(f"  {badge} {b(f.title)}")
            if f.detail:
                lines.append(f"      {f.detail}")
            if f.recommendation:
                lines.append(_c(f"      → {f.recommendation}", "dim", use_color))
            if f.evidence:
                lines.append(_c(f"      preuve : {f.evidence}", "dim", use_color))
            lines.append("")
        lines.append("")

    if not report.findings:
        lines.append(_c("  ✓ Aucun problème détecté sur les points contrôlés.", "ok", use_color))
        lines.append("")

    lines.append(_c("  Rapport généré par wp-doctor · https://wpadminlab.com", "dim", use_color))
    lines.append("")
    return "\n".join(lines)


# --- JSON -------------------------------------------------------------------

def render_json(report: Report) -> str:
    return json.dumps(report.to_dict(), ensure_ascii=False, indent=2)


# --- Markdown ---------------------------------------------------------------

def render_markdown(report: Report) -> str:
    md = []
    md.append(f"# Audit wp-doctor — {report.target}")
    md.append("")
    md.append(f"_Généré le {report.generated_at}_")
    md.append("")
    if not report.meta.get("reachable", False):
        md.append(f"**Site injoignable :** {report.meta.get('error', 'inconnu')}")
        return "\n".join(md)

    md.append(f"**Score : {report.score}/100 — Note {report.grade}**")
    md.append("")
    c = report.counts()
    md.append(f"Critiques : {c['critical']} · Élevés : {c['high']} · Moyens : {c['medium']} · Faibles : {c['low']} · Infos : {c['info']}")
    md.append("")

    wp = report.meta.get("wordpress", {})
    if wp.get("is_wordpress"):
        md.append(f"WordPress détecté — version : {wp.get('version') or 'masquée'} · thème : {wp.get('theme') or '?'}")
        md.append("")

    for cat in ["security", "performance", "seo"]:
        items = report.by_category(cat)
        if not items:
            continue
        md.append(f"## {_CAT_LABEL.get(cat, cat)}")
        md.append("")
        for f in items:
            md.append(f"### [{_LABEL[f.severity.value]}] {f.title}")
            if f.detail:
                md.append(f"{f.detail}")
            if f.recommendation:
                md.append(f"- **Recommandation :** {f.recommendation}")
            if f.evidence:
                md.append(f"- **Preuve :** `{f.evidence}`")
            md.append("")
    md.append("---")
    md.append("Rapport généré par [wp-doctor](https://wpadminlab.com) · WP Admin Lab")
    return "\n".join(md)


# --- HTML -------------------------------------------------------------------

_SEV_COLOR = {
    "critical": "#b8442b", "high": "#d9682f", "medium": "#c99a00",
    "low": "#3a7ca5", "info": "#888", "ok": "#2e8b57",
}


def render_html(report: Report) -> str:
    e = html_mod.escape
    rows = []
    for cat in ["security", "performance", "seo"]:
        items = report.by_category(cat)
        if not items:
            continue
        rows.append(f'<h2>{e(_CAT_LABEL.get(cat, cat))} <span class="count">{len(items)}</span></h2>')
        for f in items:
            sv = f.severity.value
            rows.append(f'''
    <div class="finding sev-{sv}">
      <span class="badge" style="background:{_SEV_COLOR[sv]}">{_LABEL[sv]}</span>
      <div class="fbody">
        <h3>{e(f.title)}</h3>
        {f'<p>{e(f.detail)}</p>' if f.detail else ''}
        {f'<p class="reco">→ {e(f.recommendation)}</p>' if f.recommendation else ''}
        {f'<code>{e(f.evidence)}</code>' if f.evidence else ''}
      </div>
    </div>''')

    wp = report.meta.get("wordpress", {})
    wp_line = ""
    if wp.get("is_wordpress"):
        wp_line = f"WordPress {e(wp.get('version') or '(version masquée)')} · thème {e(wp.get('theme') or '?')}"

    grade_color = {"A": "#2e8b57", "B": "#2e8b57", "C": "#c99a00", "D": "#d9682f", "F": "#b8442b"}[report.grade]

    return f'''<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Audit wp-doctor — {e(report.target)}</title>
<style>
  :root {{ --ink:#19170f; --paper:#f6f1e8; }}
  * {{ box-sizing:border-box; }}
  body {{ font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Inter,sans-serif; background:var(--paper); color:var(--ink); margin:0; padding:0 1rem 4rem; line-height:1.55; }}
  .wrap {{ max-width:820px; margin:0 auto; }}
  header {{ padding:2.5rem 0 1rem; border-bottom:2px solid var(--ink); }}
  h1 {{ font-size:1.5rem; margin:0 0 .3rem; }}
  .meta {{ color:#6b6555; font-size:.9rem; }}
  .scorecard {{ display:flex; align-items:center; gap:1.5rem; margin:1.5rem 0; padding:1.2rem 1.5rem; background:#fff; border-radius:10px; box-shadow:0 1px 4px rgba(0,0,0,.06); }}
  .grade {{ font-size:3rem; font-weight:800; color:{grade_color}; line-height:1; }}
  .score {{ font-size:1.1rem; }}
  .counts span {{ display:inline-block; margin-right:.8rem; font-size:.85rem; }}
  h2 {{ margin:2rem 0 .8rem; font-size:1.2rem; }}
  .count {{ font-size:.8rem; color:#fff; background:var(--ink); border-radius:20px; padding:.1rem .6rem; vertical-align:middle; }}
  .finding {{ display:flex; gap:.9rem; background:#fff; border-radius:8px; padding:1rem 1.1rem; margin-bottom:.7rem; box-shadow:0 1px 3px rgba(0,0,0,.05); }}
  .badge {{ color:#fff; font-size:.68rem; font-weight:700; padding:.2rem .5rem; border-radius:4px; height:fit-content; white-space:nowrap; letter-spacing:.03em; }}
  .fbody h3 {{ margin:.1rem 0 .3rem; font-size:1rem; }}
  .fbody p {{ margin:.2rem 0; font-size:.92rem; }}
  .reco {{ color:#8a5a2b; }}
  code {{ display:inline-block; margin-top:.4rem; background:#f0ebe0; padding:.15rem .45rem; border-radius:4px; font-size:.82rem; }}
  footer {{ margin-top:3rem; padding-top:1rem; border-top:1px solid #ccc; color:#6b6555; font-size:.85rem; text-align:center; }}
  footer a {{ color:#b8442b; }}
</style>
</head>
<body><div class="wrap">
  <header>
    <h1>Audit wp-doctor</h1>
    <div class="meta">{e(report.target)} · {e(report.generated_at)}<br>{wp_line}</div>
  </header>
  <div class="scorecard">
    <div class="grade">{report.grade}</div>
    <div>
      <div class="score"><strong>{report.score}/100</strong></div>
      <div class="counts">
        <span style="color:{_SEV_COLOR['critical']}">Critiques : {report.counts()['critical']}</span>
        <span style="color:{_SEV_COLOR['high']}">Élevés : {report.counts()['high']}</span>
        <span style="color:{_SEV_COLOR['medium']}">Moyens : {report.counts()['medium']}</span>
        <span style="color:{_SEV_COLOR['low']}">Faibles : {report.counts()['low']}</span>
      </div>
    </div>
  </div>
  {''.join(rows) if report.findings else '<p>✓ Aucun problème détecté sur les points contrôlés.</p>'}
  <footer>Rapport généré par <a href="https://wpadminlab.com">wp-doctor</a> — WP Admin Lab.<br>
  Audit passif et non intrusif. Utilisez-le uniquement sur des sites que vous êtes autorisé à auditer.</footer>
</div></body>
</html>'''
