"""Tests unitaires — logique pure, sans réseau."""

import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from wpdoctor.checks.seo import _disallows_all
from wpdoctor.checks.security import _looks_blocked, _is_waf_fallback
from wpdoctor.models import Report, Finding, Severity


class TestRobotsDisallow(unittest.TestCase):
    def test_disallow_all_under_star(self):
        robots = "User-agent: *\nDisallow: /\n"
        self.assertTrue(_disallows_all(robots))

    def test_disallow_all_under_bad_bot_only(self):
        # Cas réel wpadminlab : Disallow:/ sous MJ12bot, pas sous *
        robots = (
            "User-agent: *\nAllow: /\nDisallow: /wp-admin/\n\n"
            "User-agent: MJ12bot\nDisallow: /\n\n"
            "User-agent: DotBot\nDisallow: /\n\n"
            "Sitemap: https://x/sitemap.xml\n"
        )
        self.assertFalse(_disallows_all(robots))

    def test_star_grouped_with_others(self):
        # User-agent: * et Googlebot partagent le même groupe
        robots = "User-agent: Googlebot\nUser-agent: *\nDisallow: /\n"
        self.assertTrue(_disallows_all(robots))

    def test_partial_disallow_not_flagged(self):
        robots = "User-agent: *\nDisallow: /private/\n"
        self.assertFalse(_disallows_all(robots))

    def test_comments_ignored(self):
        robots = "# commentaire\nUser-agent: *  # inline\nDisallow: /\n"
        self.assertTrue(_disallows_all(robots))


class TestBlockedDetection(unittest.TestCase):
    def test_soft_403(self):
        self.assertTrue(_looks_blocked("<html><title>403 Forbidden</title>"))

    def test_soft_404(self):
        self.assertTrue(_looks_blocked("<h1>404 Not Found</h1>"))

    def test_real_file(self):
        self.assertFalse(_looks_blocked("<?php define('DB_NAME', 'x'); ?>"))

    def test_readme(self):
        self.assertFalse(_looks_blocked("<h1>WordPress</h1> Semantic Personal Publishing"))


class TestWafFallback(unittest.TestCase):
    HOME = "<html><head><title>Mon Site — Accueil</title></head><body>x</body></html>"

    def test_home_served_instead_of_git(self):
        # WAF renvoie la home à la place de .git/config
        self.assertTrue(_is_waf_fallback(".git/config", self.HOME, "Mon Site — Accueil"))

    def test_html_for_env_file(self):
        # .env censé être du texte, réponse HTML → fallback
        self.assertTrue(_is_waf_fallback(".env", "<!DOCTYPE html><html>...", ""))

    def test_real_git_config(self):
        real = "[core]\n\trepositoryformatversion = 0\n"
        self.assertFalse(_is_waf_fallback(".git/config", real, "Mon Site — Accueil"))

    def test_real_readme_not_fallback(self):
        readme = "<html><head><title>WordPress &rsaquo; ReadMe</title></head>"
        self.assertFalse(_is_waf_fallback("readme.html", readme, "Mon Site — Accueil"))


class TestScoring(unittest.TestCase):
    def test_perfect_score(self):
        r = Report(target="x", generated_at="now")
        self.assertEqual(r.score, 100)
        self.assertEqual(r.grade, "A")

    def test_critical_tanks_score(self):
        r = Report(target="x", generated_at="now")
        r.add(Finding(check="c", title="t", severity=Severity.CRITICAL, category="security"))
        self.assertEqual(r.score, 60)

    def test_counts(self):
        r = Report(target="x", generated_at="now")
        r.add(Finding(check="a", title="t", severity=Severity.HIGH, category="security"))
        r.add(Finding(check="b", title="t", severity=Severity.LOW, category="seo"))
        self.assertEqual(r.counts()["high"], 1)
        self.assertEqual(r.counts()["low"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
