#!/usr/bin/env python3
"""Scrub 1: generic identifier patterns and the DCO check.

  scrub.py identifiers [--base SHA] [--head REV] [--allow-domain DOMAIN ...]
  scrub.py dco         [--base SHA] [--head REV]

Without --base the whole history reachable from --head is scanned.

`identifiers` scans every non-merge commit in the range: the lines each commit
adds, the printable strings in the binary files it adds or changes, the paths
it touches, its message, and its author and committer, plus
the PR title and body from the PR_TITLE and PR_BODY environment variables.
It flags private addresses, emails, home paths and host names that could
identify a private deployment. Patterns are generic on purpose: no term list
is read from anywhere.

Allowed: any line containing `scrub:allow`, any file under a `docs/examples/`
folder, RFC 5737 and RFC 3849 documentation ranges, example.* domains, GitHub
noreply addresses and the public domains below (plus --allow-domain).

Exit status: 0 clean, 1 findings, 2 usage or git error.
"""

import argparse
import os
import re
import subprocess
import sys
from dataclasses import dataclass

ALLOW_MARKER = "scrub:allow"

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
    re.compile(r"(?<![\w.~$/-])/home/([A-Za-z0-9._-]+)"),  # scrub:allow
    re.compile(r"(?<![\w.~$/-])/Users/([A-Za-z0-9._-]+)"),  # scrub:allow
    re.compile(r"(?<![\w.~$/-])/code/([A-Za-z0-9._-]+)/"),  # scrub:allow
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
FQDN_PATTERNS = [
    re.compile(rf"(?<![\w.@-])((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+(?:{_TLDS}))(?![\w-]|\.\w|\()"),
    re.compile(rf"(?<![\w.@-])((?:[A-Z0-9](?:[A-Z0-9-]*[A-Z0-9])?\.)+(?:{_TLDS.upper()}))(?![\w-]|\.\w|\()"),
]
# Two-label matches that start with one of these, or with a single letter, are
# code (this.app, req.app, logger.info, o.app), not host names.
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

DOCS_EXAMPLES = re.compile(r"(?:^|/)docs/examples/")
SIGNOFF = re.compile(r"^Signed-off-by: \S.* <[^<>\s]+@[^<>\s]+>\s*$", re.M)


@dataclass
class Finding:
    cls: str
    match: str
    where: str = ""
    file: str = ""
    line: int = 0


def path_allowed(path):
    return bool(DOCS_EXAMPLES.search(path))


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

    def line(self, text, binary=False):
        """Findings in one line of text.

        binary=True is for printable runs pulled from a binary file. There, a
        neighbouring byte can glue onto a match, so home paths drop their
        left-boundary check, emails are retried with one or two glued bytes
        trimmed from either end, and host names are skipped (random bytes
        produce too many of them).
        """
        if ALLOW_MARKER in text:
            return []
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
        if binary:
            return found
        for rx in FQDN_PATTERNS:
            for m in rx.finditer(text):
                host = m.group(1)
                labels = host.split(".")
                if len(labels) == 2 and (len(labels[0]) == 1 or labels[0].lower() in CODE_RECEIVERS):
                    continue
                if not self.domain_allowed(host):
                    found.append(Finding("fqdn", host))
        return found


def git_bytes(*args):
    proc = subprocess.run(["git", "-c", "core.quotePath=false", *args],
                          capture_output=True)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr.decode("utf-8", "replace"))
        sys.exit(2)
    return proc.stdout


def git(*args):
    return git_bytes(*args).decode("utf-8", "replace")


PRINTABLE_RUN = re.compile(rb"[\x20-\x7e]{6,}")


def binary_paths(sha):
    out = git("show", "--format=", "--numstat", "--no-renames", "--diff-filter=d", "-z", sha)
    for entry in out.split("\x00"):
        parts = entry.split("\t", 2)
        if len(parts) == 3 and parts[0].strip() == "-" and parts[1] == "-":
            yield parts[2]


def commits(base, head):
    spec = f"{base}..{head}" if base else head
    return git("rev-list", "--no-merges", "--reverse", spec).split()


def _strip_prefix(path):
    path = path.strip()
    if path.startswith('"') and path.endswith('"'):
        path = path[1:-1]
    return path[2:] if path[:2] in ("a/", "b/") else path


def scan_commit(scanner, sha):
    short = sha[:12]
    out = []

    def add(findings, where, file="", line=0):
        for f in findings:
            f.where, f.file, f.line = where, file, line
            out.append(f)

    meta = git("show", "-s", "--format=%an%x00%ae%x00%cn%x00%ce%x00%B", sha).split("\x00", 4)
    an, ae, cn, ce, body = (meta + [""] * 5)[:5]
    add(scanner.line(f"{an} <{ae}>"), f"commit {short} author")
    add(scanner.line(f"{cn} <{ce}>"), f"commit {short} committer")
    for n, text in enumerate(body.splitlines(), 1):
        add(scanner.line(text), f"commit {short} commit message:{n}")

    patch = git("show", "--format=", "--no-color", "--no-ext-diff", "--no-textconv",
                "--unified=0", sha)
    path, in_hunk, lineno, seen_paths = None, False, 0, set()
    for raw in patch.splitlines():
        if raw.startswith("diff --git "):
            path, in_hunk = None, False
        elif raw.startswith("@@"):
            in_hunk = True
            m = re.match(r"@@ -\S+ \+(\d+)", raw)
            lineno = int(m.group(1)) if m else 0
        elif not in_hunk:
            if raw.startswith("+++ "):
                path = None if raw[4:].strip() == "/dev/null" else _strip_prefix(raw[4:])
            elif raw.startswith("rename to "):
                path = raw[len("rename to "):].strip().strip('"')
            else:
                continue
            if path and path not in seen_paths and not path_allowed(path):
                seen_paths.add(path)
                add(scanner.line(path), f"{path} (path, commit {short})", path)
        elif raw.startswith("+"):
            if path and not path_allowed(path):
                add(scanner.line(raw[1:]), f"{path}:{lineno} (commit {short})", path, lineno)
            lineno += 1

    # Compiled files and images can carry build paths and host names.
    for bpath in binary_paths(sha):
        if path_allowed(bpath):
            continue
        data = git_bytes("cat-file", "blob", f"{sha}:{bpath}")
        for run in PRINTABLE_RUN.findall(data):
            add(scanner.line(run.decode("ascii"), binary=True), f"{bpath} (binary, commit {short})", bpath)
    return out


def scan_pr_text(scanner):
    out = []
    for text in os.environ.get("PR_TITLE", "").splitlines():
        for f in scanner.line(text):
            f.where = "PR title"
            out.append(f)
    for n, text in enumerate(os.environ.get("PR_BODY", "").splitlines(), 1):
        for f in scanner.line(text):
            f.where = f"PR body:{n}"
            out.append(f)
    return out


def _escape(value):
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _escape_prop(value):
    return _escape(value).replace(":", "%3A").replace(",", "%2C")


def report(check, findings, describe):
    in_actions = os.environ.get("GITHUB_ACTIONS") == "true"
    for f in findings:
        print(describe(f))
        if in_actions:
            params = [f"file={_escape_prop(f.file)}", f"line={f.line}"] if f.file and f.line else []
            params.append(f"title=scrub {check}")
            print(f"::error {','.join(params)}::{_escape(describe(f))}")
    print(f"scrub {check}: {len(findings)} finding(s)")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as fh:
            fh.write(f"### scrub {check}: {len(findings)} finding(s)\n\n")
            for f in findings:
                fh.write(f"- `{describe(f)}`\n")
            fh.write("\n")
    return 1 if findings else 0


def cmd_identifiers(args):
    domains = [d for item in args.allow_domain for d in item.split()]
    scanner = Scanner(domains)
    findings = []
    for sha in commits(args.base, args.head):
        findings.extend(scan_commit(scanner, sha))
    findings.extend(scan_pr_text(scanner))
    return report("identifiers", findings, lambda f: f"{f.where}: {f.cls}: {f.match}")


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
