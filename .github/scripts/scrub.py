#!/usr/bin/env python3
"""Scrub 1: generic identifier patterns and the DCO check.

  scrub.py identifiers [--base SHA] [--head REV] [--allow-domain DOMAIN ...]
  scrub.py dco         [--base SHA] [--head REV]

Without --base the whole history reachable from --head is scanned.

`identifiers` reads, for the range:
  - every non-merge commit's own patch (so a leak added and later removed is
    still caught), plus the added lines of the net diff `base...head` once,
    which covers what merge commits add;
  - the paths those diffs touch;
  - the message, author and committer of every commit, merges included;
  - the PR title and body, from the PR_TITLE and PR_BODY environment variables.
Diffs always run with --text, so .gitattributes can't hide a file. A file whose
content has a NUL byte is binary: its ASCII, UTF-16LE and UTF-16BE string runs
are scanned instead of its lines. Compressed content (zip, docx, jar, gz, PNG
zTXt and the like) is not unpacked; scrub 2 covers it.

It flags private addresses (private-ip), emails (email), home paths
(home-path) and host names (fqdn) that could identify a private deployment.
Patterns are generic on purpose: no term list is read from anywhere.

Allowed:
  - `scrub:allow=<class>[,<class>]` on a line of a file allows those classes on
    that line. It's never honoured in commit messages, author lines, paths or
    PR text, and a bare `scrub:allow` allows nothing;
  - private-ip only, in files under the top-level `docs/examples/`;
  - RFC 5737 and RFC 3849 documentation ranges (never matched), example.*
    domains, GitHub noreply addresses and the public domains below (plus
    --allow-domain).
Every honoured allow is printed as a warning.

Exit status: 0 clean, 1 findings, 2 usage or git error.
"""

import argparse
import os
import re
import subprocess
import sys
from dataclasses import dataclass

CLASSES = ("private-ip", "email", "home-path", "fqdn")
ALLOW_MARKER = re.compile(r"scrub:allow=([a-z-]+(?:,[a-z-]+)*)")

_OCT = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
PRIVATE_IPV4 = re.compile(
    r"(?<![\w.])(?:"
    rf"10(?:\.{_OCT}){{3}}"
    rf"|172\.(?:1[6-9]|2\d|3[01])(?:\.{_OCT}){{1,2}}"
    rf"|192\.168(?:\.{_OCT}){{1,2}}"
    r")(?![\w]|\.\d)"
)
ULA_IPV6 = re.compile(r"(?<![\w:])f[cd][0-9a-f]{2}(?::[0-9a-f]{0,4}){2,7}(?![\w:])", re.I)

EMAIL = re.compile(r"(?<![\w.%+-])([A-Za-z0-9._%+-]+)@((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,})(?![\w-])")
EMAIL_ALLOWED_DOMAINS = {"users.noreply.github.com"}
EMAIL_ALLOWED_ADDRESSES = {"noreply@github.com"}

HOME_PATHS = [
    re.compile(r"(?<![\w.~$/-])/home/([A-Za-z0-9._-]+)"),  # scrub:allow=home-path
    re.compile(r"(?<![\w.~$/-])/Users/([A-Za-z0-9._-]+)"),  # scrub:allow=home-path
    re.compile(r"(?<![\w.~$/-])/code/([A-Za-z0-9._-]+)/"),  # scrub:allow=home-path
    re.compile(r"\b[A-Za-z]:\\+Users\\+([^\\\s\"'<>]+)"),
]
HOME_PATHS_BINARY = [re.compile(rx.pattern.replace(r"(?<![\w.~$/-])", "")) for rx in HOME_PATHS]
GENERIC_ACCOUNTS = {"runner", "runneradmin", "nonroot", "user", "username", "example",
                    "app", "node", "ubuntu", "Shared", "Public", "Default"}

# TLDs that commonly name a private network, then common public TLDs. TLDs that
# double as file extensions (sh, md, go, py, js, ts, rs, ...) are left out.
_TLDS = ("local|localdomain|lan|corp|internal|intranet|home|priv|private|invalid|test|int"
         "|com|net|org|io|dev|app|ai|co|cloud|edu|gov|mil|info|biz|me|us|uk|ca|de|eu|fr"
         "|nl|au|jp|tech|online|site|xyz|nyc")
_HOST = rf"(?<![\w.@-])((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+(?:{_TLDS}))"
FQDN = re.compile(_HOST + r"(?![\w-]|\.\w|\()", re.I)
FQDN_BINARY = re.compile(_HOST, re.I)
# Two-label matches are code, not host names, when they start with a single
# letter or one of these (this.app, req.app, logger.info, o.app), or look like
# a Go exported selector (time.Local, big.Int).
CODE_RECEIVERS = {"this", "self", "req", "res", "ctx", "app", "cfg", "conf", "config",
                  "opts", "options", "props", "state", "window", "document", "module",
                  "exports", "process", "logger", "log", "console", "os", "sys", "err",
                  "util", "utils", "lib"}
EXAMPLE_DOMAIN = re.compile(r"(?:^|\.)example\.[a-z]+$")
PUBLIC_DOMAINS = {
    "github.com", "githubusercontent.com", "ghcr.io", "docker.io", "docker.com", "quay.io",
    "gcr.io", "registry.k8s.io", "k8s.io", "kubernetes.io", "golang.org", "go.dev",
    "google.golang.org", "go.uber.org", "go.opentelemetry.io", "opentelemetry.io",
    "cncf.io", "apache.org", "opensource.org", "spdx.org", "developercertificate.org",
    "contributor-covenant.org", "conventionalcommits.org", "semver.org",
    "keepachangelog.com", "ietf.org", "rfc-editor.org", "w3.org", "json-schema.org",
    "schema.org", "yaml.org", "npmjs.com", "npmjs.org", "nodejs.org",
    "typescriptlang.org", "mozilla.org", "gnu.org", "k0sproject.io", "sigstore.dev",
    "slsa.dev", "openssf.org", "bestpractices.dev", "fonts.googleapis.com",
    "fonts.gstatic.com", "unpkg.com", "cdn.jsdelivr.net", "cluster.local",
}

DOCS_EXAMPLES = "docs/examples/"
SIGNOFF = re.compile(r"^Signed-off-by: \S.* <[^<>\s]+@[^<>\s]+>\s*$", re.M)


@dataclass
class Finding:
    cls: str
    match: str
    where: str = ""
    file: str = ""
    line: int = 0
    allowed_by: str = ""


def docs_example_path(path):
    return path.startswith(DOCS_EXAMPLES)


def is_code_selector(labels):
    if len(labels) != 2:
        return False
    first, last = labels
    return (len(first) == 1 or first.lower() in CODE_RECEIVERS
            or (first.islower() and last.istitle()))


class Scanner:
    def __init__(self, allowed_domains=()):
        self.allowed = PUBLIC_DOMAINS | {d.lower().strip(".") for d in allowed_domains if d}

    def domain_allowed(self, host):
        host = host.lower().rstrip(".")
        if EXAMPLE_DOMAIN.search(host):
            return True
        return any(host == d or host.endswith("." + d) for d in self.allowed)

    def email_allowed(self, local, domain):
        domain = domain.lower()
        return bool(EXAMPLE_DOMAIN.search(domain) or domain in EMAIL_ALLOWED_DOMAINS
                    or f"{local}@{domain}".lower() in EMAIL_ALLOWED_ADDRESSES
                    or (local == "git" and self.domain_allowed(domain)))

    def line(self, text, binary=False, honor_allow=True, docs_example=False):
        """Findings in one line of text; honoured allows come back with allowed_by set.

        binary=True is for string runs pulled from a binary file. There, a
        neighbouring byte can glue onto a match, so home paths drop their
        left-boundary check, host names drop their right-boundary check, and
        emails are retried with one or two glued bytes trimmed from either end.
        """
        found = self._find(text, binary)
        allowed = set()
        if honor_allow:
            for m in ALLOW_MARKER.finditer(text):
                allowed.update(c for c in m.group(1).split(",") if c in CLASSES)
        for f in found:
            if f.cls in allowed:
                f.allowed_by = f"scrub:allow={f.cls}"
            elif docs_example and f.cls == "private-ip":
                f.allowed_by = DOCS_EXAMPLES
        return found

    def _find(self, text, binary):
        found = []
        for m in PRIVATE_IPV4.finditer(text):
            found.append(Finding("private-ip", m.group(0)))
        for m in ULA_IPV6.finditer(text):
            found.append(Finding("private-ip", m.group(0)))
        for m in EMAIL.finditer(text):
            local, domain = m.group(1), m.group(2)
            trims = range(3) if binary else range(1)
            if any(self.email_allowed(local[a:], domain[:len(domain) - b])
                   for a in trims for b in trims):
                continue
            found.append(Finding("email", m.group(0)))
        for rx in (HOME_PATHS_BINARY if binary else HOME_PATHS):
            for m in rx.finditer(text):
                if m.group(1) not in GENERIC_ACCOUNTS:
                    found.append(Finding("home-path", m.group(0)))
        for m in (FQDN_BINARY if binary else FQDN).finditer(text):
            host = m.group(1)
            if is_code_selector(host.split(".")):
                continue
            if not self.domain_allowed(host):
                found.append(Finding("fqdn", host))
        return found


def git_bytes(*args, check=True):
    proc = subprocess.run(["git", "-c", "core.quotePath=false", *args],
                          capture_output=True)
    if proc.returncode != 0:
        if not check:
            return None
        sys.stderr.write(proc.stderr.decode("utf-8", "replace"))
        sys.exit(2)
    return proc.stdout


def git(*args):
    return git_bytes(*args).decode("utf-8", "replace")


ASCII_RUN = re.compile(rb"[\x20-\x7e]{6,}")
UTF16LE_RUN = re.compile(rb"(?:[\x20-\x7e]\x00){6,}")
UTF16BE_RUN = re.compile(rb"(?:\x00[\x20-\x7e]){6,}")


def string_runs(data):
    """ASCII, UTF-16LE and UTF-16BE string runs, like strings -a, -el and -eb."""
    for m in ASCII_RUN.finditer(data):
        yield m.group(0).decode("ascii")
    for m in UTF16LE_RUN.finditer(data):
        yield m.group(0)[0::2].decode("ascii")
    for m in UTF16BE_RUN.finditer(data):
        yield m.group(0)[1::2].decode("ascii")


def commits(base, head, merges=False):
    spec = f"{base}..{head}" if base else head
    args = ["rev-list", "--reverse", spec]
    if not merges:
        args.insert(1, "--no-merges")
    return git(*args).split()


def _strip_prefix(path):
    path = path.strip()
    if path.startswith('"') and path.endswith('"'):
        path = path[1:-1]
    return path[2:] if path[:2] in ("a/", "b/") else path


DIFF_OPTS = ("--text", "--no-color", "--no-ext-diff", "--no-textconv", "--no-renames",
             "--unified=0")


class Collector:
    """Collects findings, dropping repeats of the same class and match in a file."""

    def __init__(self, scanner):
        self.scanner = scanner
        self.findings = []
        self.seen = set()

    def add(self, text, where, file="", line=0, **kw):
        for f in self.scanner.line(text, **kw):
            key = (file or where, f.cls, f.match, f.allowed_by)
            if key in self.seen:
                continue
            self.seen.add(key)
            f.where, f.file, f.line = where, file, line
            self.findings.append(f)

    def patch(self, patch, blob_rev, label):
        """Scan the added lines and paths of a --text patch whose new side is blob_rev."""
        path, in_hunk, lineno, binary = None, False, 0, False
        for raw in patch.splitlines():
            if raw.startswith("diff --git "):
                path, in_hunk, binary = None, False, False
            elif raw.startswith("@@") and path is not None:
                in_hunk = True
                m = re.match(r"@@ -\S+ \+(\d+)", raw)
                lineno = int(m.group(1)) if m else 0
            elif not in_hunk:
                if raw.startswith("+++ ") and raw[4:].strip() != "/dev/null":
                    path = _strip_prefix(raw[4:])
                    docs = docs_example_path(path)
                    self.add(path, f"{path} (path, {label})", path, honor_allow=False,
                             docs_example=docs)
                    data = git_bytes("cat-file", "blob", f"{blob_rev}:{path}", check=False)
                    binary = data is not None and b"\x00" in data
                    if binary:
                        # Compiled files, images and UTF-16 text: scan their string runs.
                        for run in string_runs(data):
                            self.add(run, f"{path} (binary, {label})", path, binary=True,
                                     honor_allow=False, docs_example=docs)
            elif raw.startswith("+"):
                if path and not binary:
                    self.add(raw[1:], f"{path}:{lineno} ({label})", path, lineno,
                             docs_example=docs_example_path(path))
                lineno += 1

    def message(self, sha):
        short = sha[:12]
        meta = git("show", "-s", "--format=%an%x00%ae%x00%cn%x00%ce%x00%B", sha).split("\x00", 4)
        an, ae, cn, ce, body = (meta + [""] * 5)[:5]
        self.add(f"{an} <{ae}>", f"commit {short} author", honor_allow=False)
        self.add(f"{cn} <{ce}>", f"commit {short} committer", honor_allow=False)
        for n, text in enumerate(body.splitlines(), 1):
            self.add(text, f"commit {short} commit message:{n}", honor_allow=False)

    def pr_text(self):
        for text in os.environ.get("PR_TITLE", "").splitlines():
            self.add(text, "PR title", honor_allow=False)
        for n, text in enumerate(os.environ.get("PR_BODY", "").splitlines(), 1):
            self.add(text, f"PR body:{n}", honor_allow=False)


def _escape(value):
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _escape_prop(value):
    return _escape(value).replace(":", "%3A").replace(",", "%2C")


def report(check, findings, describe):
    in_actions = os.environ.get("GITHUB_ACTIONS") == "true"
    open_ = [f for f in findings if not f.allowed_by]
    allowed = [f for f in findings if f.allowed_by]

    def annotate(level, f, text):
        params = [f"file={_escape_prop(f.file)}", f"line={f.line}"] if f.file and f.line else []
        params.append(f"title=scrub {check}" + (" allowed" if level == "warning" else ""))
        print(f"::{level} {','.join(params)}::{_escape(text)}")

    for f in open_:
        print(describe(f))
        if in_actions:
            annotate("error", f, describe(f))
    for f in allowed:
        text = f"allowed by {f.allowed_by}: {describe(f)}"
        print(text)
        if in_actions:
            annotate("warning", f, text)
    print(f"scrub {check}: {len(open_)} finding(s), {len(allowed)} allowed")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as fh:
            fh.write(f"### scrub {check}: {len(open_)} finding(s), {len(allowed)} allowed\n\n")
            for f in open_:
                fh.write(f"- `{describe(f)}`\n")
            if allowed:
                fh.write("\nAllowed (warnings):\n\n")
                for f in allowed:
                    fh.write(f"- `{describe(f)}` allowed by `{f.allowed_by}`\n")
            fh.write("\n")
    return 1 if open_ else 0


def cmd_identifiers(args):
    domains = [d for item in args.allow_domain for d in item.split()]
    col = Collector(Scanner(domains))
    for sha in commits(args.base, args.head):
        patch = git("show", "--format=", *DIFF_OPTS, sha)
        col.patch(patch, sha, f"commit {sha[:12]}")
    # The net diff catches what merge commits add (conflict resolutions included).
    base = args.base or git("hash-object", "-t", "tree", "/dev/null").strip()
    spec = [f"{args.base}...{args.head}"] if args.base else [base, args.head]
    col.patch(git("diff", *DIFF_OPTS, *spec), args.head, "net diff")
    for sha in commits(args.base, args.head, merges=True):
        col.message(sha)
    col.pr_text()
    return report("identifiers", col.findings, lambda f: f"{f.where}: {f.cls}: {f.match}")


def cmd_dco(args):
    findings = []
    for sha in commits(args.base, args.head):
        body = git("show", "-s", "--format=%B", sha)
        if not SIGNOFF.search(body):
            subject = body.splitlines()[0] if body.strip() else ""
            findings.append(Finding("dco", subject, where=f"commit {sha[:12]}"))
    return report("dco", findings,
                  lambda f: f'{f.where} "{f.match}": no Signed-off-by trailer')


def main(argv=None):
    parser = argparse.ArgumentParser(description="Scrub 1: identifiers and DCO.")
    sub = parser.add_subparsers(dest="cmd", required=True)
    for name in ("identifiers", "dco"):
        p = sub.add_parser(name)
        p.add_argument("--base", default="", help="exclusive base commit; empty = full history")
        p.add_argument("--head", default="HEAD")
        if name == "identifiers":
            p.add_argument("--allow-domain", action="append", default=[],
                           help="extra allowed domain(s), space-separated; repeatable")
    args = parser.parse_args(argv)
    return cmd_identifiers(args) if args.cmd == "identifiers" else cmd_dco(args)


if __name__ == "__main__":
    sys.exit(main())
