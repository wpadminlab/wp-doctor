"""Interface en ligne de commande de wp-doctor."""

from __future__ import annotations

import argparse
import sys

from . import __version__
from .audit import run_audit
from . import report as report_mod


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="wp-doctor",
        description="Audit à distance d'un site WordPress : sécurité, performance, SEO. "
                    "Non intrusif, sans installation sur le site cible.",
        epilog="Exemples :\n"
               "  wp-doctor exemple.com\n"
               "  wp-doctor https://exemple.com --only security --format html -o rapport.html\n"
               "  wp-doctor exemple.com --format json | jq .score\n\n"
               "N'auditez que des sites que vous êtes autorisé à tester.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("target", help="URL ou domaine du site à auditer (ex. exemple.com)")
    p.add_argument("--only", choices=["security", "performance", "seo"], action="append",
                   help="Limiter à une ou plusieurs catégories (répétable)")
    p.add_argument("--format", choices=["terminal", "json", "markdown", "html"],
                   default="terminal", help="Format de sortie (défaut : terminal)")
    p.add_argument("-o", "--output", help="Écrire le rapport dans un fichier au lieu de stdout")
    p.add_argument("--no-color", action="store_true", help="Désactiver la couleur en sortie terminal")
    p.add_argument("--insecure", action="store_true", help="Ne pas vérifier le certificat TLS")
    p.add_argument("--quick", action="store_true", help="Audit rapide (moins de requêtes)")
    p.add_argument("--fail-on", choices=["critical", "high", "medium", "low"],
                   help="Code de sortie ≠ 0 si un finding de ce niveau (ou pire) existe. Pratique en CI.")
    p.add_argument("--version", action="version", version=f"wp-doctor {__version__}")
    return p


_ORDER = ["critical", "high", "medium", "low", "info", "ok"]


def _should_fail(report, threshold: str) -> bool:
    limit = _ORDER.index(threshold)
    for f in report.findings:
        if _ORDER.index(f.severity.value) <= limit:
            return True
    return False


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    categories = args.only or ["security", "performance", "seo"]

    try:
        report = run_audit(
            args.target,
            categories=categories,
            verify_tls=not args.insecure,
            quick=args.quick,
        )
    except KeyboardInterrupt:
        print("\nInterrompu.", file=sys.stderr)
        return 130

    if args.format == "json":
        out = report_mod.render_json(report)
    elif args.format == "markdown":
        out = report_mod.render_markdown(report)
    elif args.format == "html":
        out = report_mod.render_html(report)
    else:
        use_color = (not args.no_color) and sys.stdout.isatty() and not args.output
        out = report_mod.render_terminal(report, use_color=use_color)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out)
        print(f"Rapport écrit dans {args.output}", file=sys.stderr)
    else:
        print(out)

    if args.fail_on and _should_fail(report, args.fail_on):
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
