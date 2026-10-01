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


def classes(text, allowed_domains=(), **kw):
    return [f.cls for f in scrub.Scanner(allowed_domains).line(text, **kw) if not f.allowed_by]


def allowed(text, **kw):
    return [(f.cls, f.allowed_by) for f in scrub.Scanner().line(text, **kw) if f.allowed_by]


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

    def test_ipv4_after_letter_or_underscore_flagged(self):
        for text in (j("node_10.1", ".2.3"), j("srv10.1", ".2.3"), j("db_192.168", ".7.8"),
                     j("ip=x172.20", ".4.5")):
            self.assertEqual(classes(text), ["private-ip"], text)

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


class EmailExampleDomainTest(unittest.TestCase):
    def test_only_the_three_example_domains_allowed(self):
        for text in (j("a@example", ".io"), j("b@example", ".dev"), j("c@mail", ".example", ".co")):
            self.assertEqual(classes(text), ["email"], text)


class HomePathTest(unittest.TestCase):
    def test_home_paths_flagged(self):
        for text in (j("/ho", "me/jdoe/src"), j("/Us", "ers/jdoe/Desktop"),
                     j("/co", "de/jdoe/project"), j("C:\\Us", "ers\\jdoe\\x")):
            self.assertEqual(classes(text), ["home-path"], text)

    def test_code_path_without_trailing_slash_flagged(self):
        for text in (j("cd /co", "de/jdoe"), j("root=/co", "de/jdoe;"), j("/co", "de/jdoe")):
            self.assertEqual(classes(text), ["home-path"], text)

    def test_file_urls_flagged(self):
        for text in (j("file:///ho", "me/jdoe/x"), j("see file:///Us", "ers/jdoe"),
                     j("file://localhost/ho", "me/jdoe/x")):
            self.assertEqual(classes(text), ["home-path"], text)
        self.assertEqual(classes(j("file:///ho", "me/runner/work")), [])

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

    def test_mixed_case_hosts_flagged(self):
        for text in (j("Dc01", ".Corp", ".Local"), j("https://Wiki", ".Acme-Corp", ".Com/x"),
                     j("Corp", ".Local")):
            self.assertEqual(classes(text), ["fqdn"], text)

    def test_go_exported_selectors_pass(self):
        for text in ("t := time.Local", "n := new(big.Int)", "k == reflect.Int"):
            self.assertEqual(classes(text), [], text)

    def test_email_domain_not_double_reported(self):
        self.assertEqual(classes(EMAIL_BAD), ["email"])


class AllowTest(unittest.TestCase):
    def test_marker_is_class_specific(self):
        line = "host = " + IP_10 + " see " + HOST_BAD
        self.assertEqual(classes(line + "  # scrub:allow=private-ip"), ["fqdn"])
        self.assertEqual(allowed(line + "  # scrub:allow=private-ip"),
                         [("private-ip", "scrub:allow=private-ip")])
        self.assertEqual(classes(line + "  # scrub:allow=private-ip,fqdn"), [])

    def test_bare_marker_allows_nothing(self):
        self.assertEqual(classes("host = " + IP_10 + "  # scrub:allow"), ["private-ip"])

    def test_marker_ignored_when_not_honoured(self):
        line = "host = " + IP_10 + "  # scrub:allow=private-ip"
        self.assertEqual(classes(line, honor_allow=False), ["private-ip"])

    def test_docs_examples_only_root_and_only_private_ip(self):
        self.assertTrue(scrub.docs_example_path("docs/examples/lab.md"))
        self.assertFalse(scrub.docs_example_path("svc/docs/examples/a/b.yaml"))
        self.assertFalse(scrub.docs_example_path("docs/install.md"))
        line = "host = " + IP_10 + " mail " + EMAIL_BAD
        self.assertEqual(classes(line, docs_example=True), ["email"])
        self.assertEqual(allowed(line, docs_example=True), [("private-ip", "docs/examples/")])


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

    def test_gitattributes_cannot_hide_text(self):
        self.commit(".gitattributes", "* -diff\n", "chore: attrs" + SIGNOFF)
        self.commit("hosts.txt", "upstream " + HOST_BAD + "\n", "test: add" + SIGNOFF)
        head = git(self.repo, "rev-parse", "HEAD")
        ids = self.run_scrub("identifiers", "--base", self.base, "--head", head)
        self.assertEqual(ids.returncode, 1, ids.stdout + ids.stderr)
        self.assertIn("hosts.txt:1", ids.stdout)
        self.assertIn("fqdn", ids.stdout)

    def test_utf16_files_scanned(self):
        text = "upstream " + HOST_BAD + "\nhost " + IP_10 + "\n"
        for name, enc in (("le.txt", "utf-16-le"), ("be.txt", "utf-16-be"), ("bom.txt", "utf-16")):
            with open(os.path.join(self.repo, name), "wb") as fh:
                fh.write(text.encode(enc))
        git(self.repo, "add", ".")
        git(self.repo, "-c", "core.hooksPath=/dev/null", "commit", "-q", "-m", "test: add" + SIGNOFF)
        head = git(self.repo, "rev-parse", "HEAD")
        ids = self.run_scrub("identifiers", "--base", self.base, "--head", head)
        self.assertEqual(ids.returncode, 1, ids.stdout + ids.stderr)
        for name in ("le.txt", "be.txt", "bom.txt"):
            lines = [x for x in ids.stdout.splitlines() if x.startswith(name)]
            self.assertTrue(any("fqdn" in x for x in lines), (name, ids.stdout))
            self.assertTrue(any("private-ip" in x for x in lines), (name, ids.stdout))

    def test_paths_git_quotes_are_scanned(self):
        names = ("we\tird.txt", 'q"uo\\te.txt', "new\nline.txt")
        with open(os.path.join(self.repo, names[0]), "wb") as fh:
            fh.write(("upstream " + HOST_BAD + "\n").encode("utf-16"))
        for name in names[1:]:
            with open(os.path.join(self.repo, name), "w") as fh:
                fh.write("upstream " + HOST_BAD + "\n")
        git(self.repo, "add", "-A")
        git(self.repo, "-c", "core.hooksPath=/dev/null", "commit", "-q", "-m", "test: add" + SIGNOFF)
        head = git(self.repo, "rev-parse", "HEAD")
        ids = self.run_scrub("identifiers", "--base", self.base, "--head", head)
        self.assertEqual(ids.returncode, 1, ids.stdout + ids.stderr)
        self.assertIn("we\\tird.txt (binary, commit", ids.stdout)
        self.assertIn('q"uo\\\\te.txt:1 (commit', ids.stdout)
        self.assertIn("new\\nline.txt:1 (commit", ids.stdout)

    def test_unreadable_blob_is_an_error(self):
        self.commit("a.txt", "harmless\n", "test: add" + SIGNOFF)
        blob = git(self.repo, "rev-parse", "HEAD:a.txt")
        os.remove(os.path.join(self.repo, ".git", "objects", blob[:2], blob[2:]))
        head = git(self.repo, "rev-parse", "HEAD")
        ids = self.run_scrub("identifiers", "--base", self.base, "--head", head)
        self.assertEqual(ids.returncode, 2, ids.stdout + ids.stderr)

    def test_marker_not_honoured_in_messages_or_pr_text(self):
        marker = " scrub:allow=private-ip"
        self.commit("a.txt", "clean\n", "fix: reach " + IP_10 + marker + SIGNOFF)
        head = git(self.repo, "rev-parse", "HEAD")
        ids = self.run_scrub("identifiers", "--base", self.base, "--head", head,
                             env={"PR_TITLE": "fix: " + IP_172 + marker,
                                  "PR_BODY": "see " + IP_192 + marker})
        self.assertIn("commit message", ids.stdout)
        self.assertIn("PR title", ids.stdout)
        self.assertIn("PR body:1", ids.stdout)
        self.assertIn("3 finding(s)", ids.stdout)

    def test_honoured_allows_are_warnings(self):
        self.commit("a.txt", "host = " + IP_10 + "  # scrub:allow=private-ip\n",
                    "test: add" + SIGNOFF)
        os.makedirs(os.path.join(self.repo, "docs", "examples"))
        self.commit("docs/examples/lab.md", "lab " + IP_172 + "\n", "docs: add" + SIGNOFF)
        head = git(self.repo, "rev-parse", "HEAD")
        summary = os.path.join(self.repo, ".summary")
        ids = self.run_scrub("identifiers", "--base", self.base, "--head", head,
                             env={"GITHUB_ACTIONS": "true", "GITHUB_STEP_SUMMARY": summary})
        self.assertEqual(ids.returncode, 0, ids.stdout + ids.stderr)
        self.assertIn("::warning file=a.txt,line=1,", ids.stdout)
        self.assertIn("::warning file=docs/examples/lab.md,line=1,", ids.stdout)
        self.assertIn("0 finding(s), 2 allowed", ids.stdout)
        with open(summary) as fh:
            body = fh.read()
        self.assertIn("allowed", body)
        self.assertIn("scrub:allow=private-ip", body)
        self.assertIn("docs/examples/", body)

    def test_merge_commits_scanned(self):
        git(self.repo, "switch", "-q", "-c", "topic")
        self.commit("t.txt", "topic\n", "feat: topic" + SIGNOFF)
        git(self.repo, "switch", "-q", "main")
        self.commit("m.txt", "main\n", "feat: main" + SIGNOFF)
        git(self.repo, "-c", "core.hooksPath=/dev/null", "merge", "-q", "--no-ff",
            "--no-commit", "topic")
        with open(os.path.join(self.repo, "evil.txt"), "w") as fh:
            fh.write("host = " + IP_10 + "\n")
        git(self.repo, "add", "evil.txt")
        git(self.repo, "-c", "core.hooksPath=/dev/null", "commit", "-q",
            "-m", "Merge topic via " + HOST_BAD + SIGNOFF)
        head = git(self.repo, "rev-parse", "HEAD")
        ids = self.run_scrub("identifiers", "--base", self.base, "--head", head)
        self.assertEqual(ids.returncode, 1, ids.stdout + ids.stderr)
        self.assertIn("evil.txt:1", ids.stdout)
        self.assertIn("commit message", ids.stdout)
        self.assertIn("2 finding(s)", ids.stdout)

    def test_line_separators_cannot_hide_text(self):
        for ch, name in (("\r", "cr"), ("\x0c", "ff"), ("\x85", "nel")):
            with self.subTest(name):
                fname = f"sep-{name}.txt"
                with open(os.path.join(self.repo, fname), "w", encoding="utf-8", newline="") as fh:
                    fh.write("ok line" + ch + "host " + HOST_BAD + ch + "addr " + IP_10 + "\n")
                git(self.repo, "add", fname)
                git(self.repo, "-c", "core.hooksPath=/dev/null", "commit", "-q",
                    "-m", "test: add" + SIGNOFF)
                head = git(self.repo, "rev-parse", "HEAD")
                ids = self.run_scrub("identifiers", "--base", self.base, "--head", head)
                lines = [x for x in ids.stdout.splitlines() if x.startswith(fname)]
                self.assertTrue(any("fqdn" in x for x in lines), (name, ids.stdout))
                self.assertTrue(any("private-ip" in x for x in lines), (name, ids.stdout))

    def test_line_separators_cannot_hide_pr_or_message_text(self):
        for ch, name in (("\r", "cr"), ("\x0c", "ff"), ("\x85", "nel")):
            with self.subTest(name):
                self.commit(f"m-{name}.txt", "clean\n",
                            "fix: ok" + ch + "via " + HOST_BAD + SIGNOFF)
                head = git(self.repo, "rev-parse", "HEAD")
                ids = self.run_scrub("identifiers", "--base", f"{head}~1", "--head", head,
                                     env={"PR_TITLE": "fix: ok" + ch + IP_172,
                                          "PR_BODY": "fine" + ch + "see " + IP_192})
                self.assertIn("commit message", ids.stdout, name)
                self.assertIn("PR title", ids.stdout, name)
                self.assertIn("PR body:1", ids.stdout, name)
                self.assertIn("3 finding(s)", ids.stdout, name)

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
