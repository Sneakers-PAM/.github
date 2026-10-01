#!/usr/bin/env python3
"""Tests for scrub.py. Run: python3 .github/scripts/scrub_test.py

Fake identifiers are assembled from parts so this file never carries a
literal one and stays clean under its own scan.
"""

import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import scrub  # noqa: E402

SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scrub.py")


def j(*parts):
    return "".join(parts)


IP_10 = j("10.1", ".2.3")
IP_172 = j("172.20", ".4.5")
IP_192 = j("192.168", ".7.8")
EMAIL_BAD = j("user@corp", ".invalid")
HOST_BAD = j("build01", ".corp", ".invalid")


def classes(text, allowed_domains=()):
    return [f.cls for f in scrub.Scanner(allowed_domains).line(text)]


class PrivateAddressTest(unittest.TestCase):
    def test_rfc1918_flagged(self):
        for ip in (IP_10, IP_172, IP_192):
            self.assertEqual(classes("host = " + ip), ["private-ip"], ip)

    def test_partial_172_and_192_prefixes_flagged(self):
        self.assertEqual(classes("the " + j("172.1", "6.9") + " net"), ["private-ip"])
        self.assertEqual(classes("route " + j("192.168", ".40") + ".0/24"), ["private-ip"])

    def test_cidr_flagged(self):
        self.assertEqual(classes("cidr: " + j("10.20", ".0.0/16")), ["private-ip"])

    def test_public_and_documentation_ranges_pass(self):
        for text in ("dns 8.8.8.8", "doc 192.0.2.10", "doc 198.51.100.7",
                     "doc 203.0.113.9", "dns 1.1.1.1", j("near 172.32", ".1.1")):
            self.assertEqual(classes(text), [], text)

    def test_version_strings_pass(self):
        for text in ("go 1.10.2", "release 10.1.2", "v10.1.2.3", "pkg@10.1.2"):
            self.assertEqual(classes(text), [], text)

    def test_ula_ipv6_flagged_and_documentation_ipv6_passes(self):
        self.assertEqual(classes("addr " + j("fd12", ":3456:789a::1")), ["private-ip"])
        self.assertEqual(classes("addr 2001:db8::1"), [])


class EmailTest(unittest.TestCase):
    def test_non_example_domain_flagged(self):
        self.assertEqual(classes("contact = " + EMAIL_BAD), ["email"])

    def test_example_and_noreply_pass(self):
        for text in ("a@example.com", "b@mail.example.org", "c@example.net",
                     "12345+someone@users.noreply.github.com",
                     "GitHub <noreply@github.com>",
                     "git clone git@github.com:Sneakers-PAM/plan.git",
                     "uses: org/repo/.github/workflows/x.yml@main",
                     "npm i left-pad@1.3.0", "image@sha256:abcdef"):
            self.assertEqual(classes(text), [], text)


class HomePathTest(unittest.TestCase):
    def test_home_paths_flagged(self):
        for text in (j("/ho", "me/jdoe/src"), j("/Us", "ers/jdoe/Desktop"),
                     j("/co", "de/jdoe/project"), j("C:\\Us", "ers\\jdoe\\x")):
            self.assertEqual(classes(text), ["home-path"], text)

    def test_generic_accounts_pass(self):
        for text in (j("/ho", "me/runner/work"), j("/ho", "me/nonroot"),
                     "$HOME/.config", "~/.config", "cd /home/"):
            self.assertEqual(classes(text), [], text)


class FqdnTest(unittest.TestCase):
    def test_private_style_hosts_flagged(self):
        for text in ("see " + HOST_BAD, j("ldap://dc01", ".corp", ".local"),
                     j("DC01", ".CORP", ".LOCAL"), j("https://wiki", ".acme-corp", ".com/x"),
                     j("nas.", "home")):
            self.assertEqual(classes(text), ["fqdn"], text)

    def test_public_and_example_hosts_pass(self):
        for text in ("https://github.com/Sneakers-PAM", "api.github.com",
                     "postgres.sneakers.svc.cluster.local", "www.example.net",
                     "docs.example.io", "golang.org/x/crypto", "k8s.io/api",
                     "https://developercertificate.org/"):
            self.assertEqual(classes(text), [], text)

    def test_code_and_file_names_pass(self):
        for text in ("log.info(\"x\")", "config.yaml", "install.sh", "main.go",
                     "README.md", "os.Stdout.Write", "re.test(s)"):
            self.assertEqual(classes(text), [], text)

    def test_project_domain_allowed_by_input(self):
        host = j("docs", ".sneakers-pam", ".dev")
        self.assertEqual(classes(host), ["fqdn"])
        self.assertEqual(classes(host, [j("sneakers-pam", ".dev")]), [])

    def test_email_domain_not_double_reported(self):
        self.assertEqual(classes(EMAIL_BAD), ["email"])


class AllowTest(unittest.TestCase):
    def test_marker_allows_line(self):
        self.assertEqual(classes("host = " + IP_10 + "  # scrub:allow"), [])

    def test_docs_examples_path_allowed(self):
        self.assertTrue(scrub.path_allowed("docs/examples/lab.md"))
        self.assertTrue(scrub.path_allowed("svc/docs/examples/a/b.yaml"))
        self.assertFalse(scrub.path_allowed("docs/install.md"))


def git(cwd, *args, env=None):
    full = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM="1",
                GIT_AUTHOR_NAME="Test", GIT_AUTHOR_EMAIL="test@example.com",
                GIT_COMMITTER_NAME="Test", GIT_COMMITTER_EMAIL="test@example.com")
    if env:
        full.update(env)
    return subprocess.run(["git", *args], cwd=cwd, env=full, check=True,
                          capture_output=True, text=True).stdout.strip()


SIGNOFF = "\n\nSigned-off-by: Test <test@example.com>"


class EndToEndTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = self.tmp.name
        git(self.repo, "init", "-q", "-b", "main")
        git(self.repo, "-c", "core.hooksPath=/dev/null", "commit", "-q",
            "--allow-empty", "-m", "chore: init" + SIGNOFF)
        self.base = git(self.repo, "rev-parse", "HEAD")

    def tearDown(self):
        self.tmp.cleanup()

    def commit(self, name, content, message):
        with open(os.path.join(self.repo, name), "w") as fh:
            fh.write(content)
        git(self.repo, "add", name)
        git(self.repo, "-c", "core.hooksPath=/dev/null", "commit", "-q", "-m", message)

    def run_scrub(self, *args, env=None):
        full = dict(os.environ, PR_TITLE="", PR_BODY="")
        full.pop("GITHUB_ACTIONS", None)
        full.pop("GITHUB_STEP_SUMMARY", None)
        if env:
            full.update(env)
        return subprocess.run([sys.executable, SCRIPT, *args], cwd=self.repo, env=full,
                              capture_output=True, text=True)

    def test_three_bad_commits(self):
        self.commit("a.txt", "host = " + IP_10 + "\n", "test: add an address" + SIGNOFF)
        self.commit("b.txt", "contact = " + EMAIL_BAD + "\n", "test: add a contact" + SIGNOFF)
        self.commit("c.txt", "clean\n", "test: add an unsigned commit")
        head = git(self.repo, "rev-parse", "HEAD")

        ids = self.run_scrub("identifiers", "--base", self.base, "--head", head)
        self.assertEqual(ids.returncode, 1, ids.stdout + ids.stderr)
        self.assertIn("a.txt:1", ids.stdout)
        self.assertIn("b.txt:1", ids.stdout)
        self.assertIn("2 finding(s)", ids.stdout)

        dco = self.run_scrub("dco", "--base", self.base, "--head", head)
        self.assertEqual(dco.returncode, 1, dco.stdout + dco.stderr)
        self.assertIn("test: add an unsigned commit", dco.stdout)
        self.assertIn("1 finding(s)", dco.stdout)

    def test_github_annotations(self):
        self.commit("a.txt", "host = " + IP_10 + "\n", "test: add an address")
        head = git(self.repo, "rev-parse", "HEAD")
        env = {"GITHUB_ACTIONS": "true"}
        ids = self.run_scrub("identifiers", "--base", self.base, "--head", head, env=env)
        self.assertIn("::error file=a.txt,line=1,title=scrub identifiers::", ids.stdout)
        dco = self.run_scrub("dco", "--base", self.base, "--head", head, env=env)
        self.assertIn("::error title=scrub dco::", dco.stdout)

    def test_strings_in_binary_files_scanned(self):
        blob = (b"\x00\x01Z" + j("/ho", "me/jdoe/build/x.py").encode()
                + b"\x00)noreply@github" + b".comz\x00\xff\xfe")
        with open(os.path.join(self.repo, "x.bin"), "wb") as fh:
            fh.write(blob)
        git(self.repo, "add", "x.bin")
        git(self.repo, "-c", "core.hooksPath=/dev/null", "commit", "-q", "-m", "test: add" + SIGNOFF)
        head = git(self.repo, "rev-parse", "HEAD")
        ids = self.run_scrub("identifiers", "--base", self.base, "--head", head)
        self.assertEqual(ids.returncode, 1, ids.stdout + ids.stderr)
        self.assertIn("x.bin (binary, commit", ids.stdout)
        self.assertIn("home-path", ids.stdout)
        self.assertIn("1 finding(s)", ids.stdout)

    def test_leak_added_then_removed_is_still_flagged(self):
        self.commit("a.txt", "host = " + IP_10 + "\n", "test: add" + SIGNOFF)
        self.commit("a.txt", "host = 192.0.2.1\n", "test: fix" + SIGNOFF)
        head = git(self.repo, "rev-parse", "HEAD")
        ids = self.run_scrub("identifiers", "--base", self.base, "--head", head)
        self.assertEqual(ids.returncode, 1)
        self.assertIn("1 finding(s)", ids.stdout)

    def test_commit_message_author_and_pr_text_scanned(self):
        self.commit("a.txt", "clean\n", "fix: reach " + HOST_BAD + SIGNOFF)
        git(self.repo, "-c", "core.hooksPath=/dev/null", "commit", "-q", "--allow-empty",
            "-m", "chore: x" + SIGNOFF, env={"GIT_AUTHOR_EMAIL": EMAIL_BAD})
        head = git(self.repo, "rev-parse", "HEAD")
        ids = self.run_scrub("identifiers", "--base", self.base, "--head", head,
                             env={"PR_TITLE": "fix: things", "PR_BODY": "line one\nsee " + IP_192})
        self.assertEqual(ids.returncode, 1)
        self.assertIn("commit message", ids.stdout)
        self.assertIn("author", ids.stdout)
        self.assertIn("PR body:2", ids.stdout)
        self.assertIn("3 finding(s)", ids.stdout)

    def test_clean_range_passes_and_full_history_works(self):
        self.commit("a.txt", "host = 192.0.2.1\nmail a@example.com\n", "feat: add" + SIGNOFF)
        head = git(self.repo, "rev-parse", "HEAD")
        for args in (("--base", self.base, "--head", head), ("--head", head)):
            ids = self.run_scrub("identifiers", *args)
            self.assertEqual(ids.returncode, 0, ids.stdout + ids.stderr)
            dco = self.run_scrub("dco", *args)
            self.assertEqual(dco.returncode, 0, dco.stdout + dco.stderr)


if __name__ == "__main__":
    unittest.main()
