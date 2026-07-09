# wp-doctor 🩺

**Audit à distance d'un site WordPress : sécurité, performance et SEO technique.**
Aucune installation sur le site cible, aucune dépendance, non intrusif.

[![Python](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Tests](https://github.com/wpadminlab/wp-doctor/actions/workflows/tests.yml/badge.svg)](https://github.com/wpadminlab/wp-doctor/actions)

`wp-doctor` interroge un site WordPress uniquement via des requêtes HTTP publiques
et produit un rapport noté (score /100 + note A→F) sur trois axes :

- **🔒 Sécurité** — fichiers sensibles exposés (`.env`, `wp-config.php.bak`, `.git/config`…),
  `xmlrpc.php` ouvert, énumération des utilisateurs (API REST & `?author=1`), en-têtes de
  sécurité manquants (HSTS, CSP, X-Frame-Options), version WordPress exposée, listing de répertoires.
- **⚡ Performance** — temps de réponse serveur (TTFB), cache de page, compression gzip/brotli,
  poids du HTML, images sans lazy-loading, nombre de ressources bloquantes.
- **🔍 SEO technique** — `title`, meta description, canonical, Open Graph, données structurées
  (JSON-LD / microdata), `robots.txt`, sitemap, `noindex` accidentel, attribut `lang`, hiérarchie des titres.

> ⚠️ **Usage responsable.** N'auditez que des sites qui vous appartiennent ou pour lesquels
> vous avez une autorisation explicite. `wp-doctor` est passif (aucune exploitation, aucun
> brute-force, aucune écriture) mais reste un outil d'audit.

---

## Installation

```bash
# Depuis les sources
git clone https://github.com/wpadminlab/wp-doctor.git
cd wp-doctor
pip install .
```

Aucune dépendance externe : `wp-doctor` n'utilise que la bibliothèque standard Python (≥ 3.8).
Vous pouvez aussi le lancer sans installer :

```bash
python3 -m wpdoctor exemple.com
```

## Utilisation

```bash
# Audit complet, sortie terminal colorée
wp-doctor exemple.com

# Une seule catégorie
wp-doctor exemple.com --only security

# Rapport HTML autonome
wp-doctor exemple.com --format html -o rapport.html

# JSON pour l'intégration (CI, dashboards)
wp-doctor exemple.com --format json | jq '.score'

# En intégration continue : échec si un problème critique est détecté
wp-doctor exemple.com --fail-on critical
```

### Options

| Option | Description |
|--------|-------------|
| `--only {security,performance,seo}` | Limiter à une/plusieurs catégories (répétable) |
| `--format {terminal,json,markdown,html}` | Format de sortie (défaut : `terminal`) |
| `-o, --output FICHIER` | Écrire dans un fichier au lieu de stdout |
| `--fail-on {critical,high,medium,low}` | Code de sortie ≠ 0 au-delà de ce seuil (CI) |
| `--quick` | Audit rapide (moins de requêtes) |
| `--insecure` | Ne pas vérifier le certificat TLS |
| `--no-color` | Désactiver la couleur |

## Exemple de sortie

```
  wp-doctor — audit de https://exemple.com/
  WordPress détecté — 6.5 · thème : astra

   Score : 62/100   Note : C
  MOYEN: 3  FAIBLE: 2  INFO: 2

  🔒 Sécurité  (7)
   MOYEN  Énumération des utilisateurs via l'API REST
      wp-json/wp/v2/users expose 1 identifiant(s) : admin
      → Restreindre l'endpoint users de l'API REST.
   ...
```

Un exemple de rapport HTML est disponible dans [`docs/exemple-rapport.html`](docs/exemple-rapport.html).

## Comment fonctionne le score

Chaque problème détecté retire des points selon sa gravité
(critique −40, élevé −20, moyen −10, faible −4). Le score part de 100.
La note va de **A** (≥ 90) à **F** (< 40).

## Développement

```bash
python3 -m unittest discover tests -v
```

Les vérifications sont des modules indépendants dans [`wpdoctor/checks/`](wpdoctor/checks/).
Ajouter une vérification = ajouter une fonction qui retourne des `Finding`. Contributions bienvenues.

## Pourquoi wp-doctor ?

Créé et maintenu par [**WP Admin Lab**](https://wpadminlab.com), blog francophone dédié à
WordPress, au développement web et à l'IA. On avait besoin d'un audit rapide et reproductible
pour vérifier nos propres sites — le voici, ouvert à tous.

📖 Guides détaillés sur chaque point audité : [wpadminlab.com](https://wpadminlab.com)

## Licence

[MIT](LICENSE) © WP Admin Lab
