#!/usr/bin/env python3
"""Scrub 1: generic identifier patterns and the DCO check.

  scrub.py identifiers [--base SHA] [--head REV] [--allow-domain DOMAIN ...]
                       [--allow-file FILE [--allow-label LABEL]] [--check-allow-file FILE]
  scrub.py dco         [--base SHA] [--head REV]

Without --base the whole history reachable from --head is scanned.

`identifiers` reads, for the range:
  - every non-merge commit's own patch (so a leak added and later removed is
    still caught), plus the added lines of the net diff `base...head` once,
    which covers what merge commits add;
  - the paths those diffs touch;
  - the message, author and committer of every commit, merges included;
  - the PR title and body, from the PR_TITLE and PR_BODY environment variables.
Files are listed with NUL-separated plumbing and read by blob id, so no path
(tab, quote, backslash or newline in the name) can hide its content, and a
blob that can't be read is an error (exit 2). Diffs always run with --text, so
.gitattributes can't hide a file. A file whose content has a NUL byte is
binary: its ASCII, UTF-16LE and UTF-16BE string runs are scanned instead of its
lines, except in font files, whose strings are glyph names. Compressed content (zip, docx, jar, gz, PNG
zTXt and the like) is not unpacked; scrub 2 covers it.

It flags private addresses (private-ip, also when glued to a name such as
node_10.x; a lone v prefix reads as a version), emails (email), home paths
(home-path: /home/<name>, /Users/<name>, /code/<name>, C:\\Users\\<name> and
file:// URLs to them) and host names (fqdn) that could identify a private
deployment.
It also flags provenance metadata (provenance: C2PA manifests and JUMBF boxes)
in images, icons, PDFs and SVGs. No allow marker covers it.
Patterns are generic on purpose: no term list is read from anywhere.

Allowed:
  - `scrub:allow=<class>[,<class>]` on a line of a file allows those classes on
    that line. It's never honoured in commit messages, author lines, paths or
    PR text, and a bare `scrub:allow` allows nothing;
  - an entry of the repo's reviewed allowlist, `.github/scrub-allow.txt`, passed
    with --allow-file as the caller read it from the base side of the change:
    `<class> <exact value> <path glob>  # reason`, one exact value in the files
    the glob matches, on file lines only (never messages, authors, paths, binary
    string runs or PR text). A malformed list is an error (exit 2), and
    --check-allow-file checks the PR's own copy without applying it. Secrets
    can't be listed. A well-formed entry line in the list itself allows its own
    value on that line;
  - private-ip only, in files under the top-level `docs/examples/`;
  - RFC 5737 and RFC 3849 documentation ranges (never matched); emails at
    example.com, example.org and example.net (and their subdomains) only; host
    names under any example.* domain; GitHub noreply addresses, the public
    domains below and the project's own domain, sneakers-pam.com, as host
    names (plus --allow-domain);
  - an allowed host name with protobuf bytes glued on in front, as in a
    protoc-gen-go raw descriptor (up to four layers of a string field's tag byte,
    a length byte that fits the value, or \\xNN escapes, so go_package inside
    the file options message counts). After those bytes are stripped, the rest
    must be an allowed domain, so a private host name in a descriptor is still
    flagged;
  - host names (fqdn only) in generated code: a text file whose leading
    comments carry the standard `// Code generated ... DO NOT EDIT.` line, before
    any code. Protobuf descriptors there can glue a message name, length bytes
    and a package path into what reads as one host. Every other class is still
    flagged in generated code, so a home path or address a generator embedded
    still fails.
Every honoured allow is printed as a warning.

Exit status: 0 clean, 1 findings, 2 usage or git error.
"""

import argparse
import fnmatch
import os
import re
import subprocess
import sys
from dataclasses import dataclass

CLASSES = ("private-ip", "email", "home-path", "fqdn")
ALLOW_MARKER = re.compile(r"scrub:allow=([a-z-]+(?:,[a-z-]+)*)")

_OCT = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
PRIVATE_IPV4 = re.compile(
    r"(?<![\d.])(?<!(?<![A-Za-z0-9_])[vV])(?:"
    rf"10(?:\.{_OCT}){{3}}"
    rf"|172\.(?:1[6-9]|2\d|3[01])(?:\.{_OCT}){{1,2}}"
    rf"|192\.168(?:\.{_OCT}){{1,2}}"
    r")(?![\w]|\.\d)"
)
ULA_IPV6 = re.compile(r"(?<![\w:])f[cd][0-9a-f]{2}(?::[0-9a-f]{0,4}){2,7}(?![\w:])", re.I)

EMAIL = re.compile(r"(?<![\w.%+-])([A-Za-z0-9._%+-]+)@((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,})(?![\w-])")
EMAIL_ALLOWED_DOMAINS = {"users.noreply.github.com"}
EMAIL_EXAMPLE_DOMAIN = re.compile(r"(?:^|\.)example\.(?:com|org|net)$")
EMAIL_ALLOWED_ADDRESSES = {"noreply@github.com"}

HOME_PATHS = [
    re.compile(r"(?<![\w.~$/-])/home/([A-Za-z0-9._-]+)"),  # scrub:allow=home-path
    re.compile(r"(?<![\w.~$/-])/Users/([A-Za-z0-9._-]+)"),  # scrub:allow=home-path
    re.compile(r"(?<![\w.~$/-])/code/([A-Za-z0-9._-]+)"),  # scrub:allow=home-path
    re.compile(r"\bfile://[^/\s]*/(?:home|Users|code)/([A-Za-z0-9._-]+)", re.I),
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
    "sil.org",  # scrub:allow=fqdn
}
# The project's own domain and its sibling products' domains, accepted as host
# names (and their subdomains) in every repo. Emails at them are still flagged.
ORG_DOMAINS = {"sneakers-pam.com", "steward-grc.com", "brigade-itsm.com"}  # scrub:allow=fqdn

DOCS_EXAMPLES = "docs/examples/"

# Provenance metadata some export tools embed in assets: C2PA manifests in
# JUMBF boxes (PNG caBX chunks, JPEG APP11, SVG metadata). Only these file
# types are checked, so marker bytes in other binaries never match by chance.
ASSET_EXTENSIONS = (".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".heic", ".tif",
                    ".tiff", ".ico", ".svg", ".pdf")
# Typefaces are vendor files whose strings are glyph names, a copyright line and the licence
# address, never a place a private identifier lives. Their path is still scanned, and every
# other binary file has its string runs scanned as before.
FONT_EXTENSIONS = (".ttf", ".otf", ".ttc", ".woff", ".woff2")
PROVENANCE = re.compile(rb"c2pa|C2PA|caBX|jumb|contentauth")
SIGNOFF = re.compile(r"^Signed-off-by: \S.* <[^<>\s]+@[^<>\s]+>\s*$", re.M)


# Go's convention for generated files (also used by other generators): this exact
# line among the leading comments, before the first line of code.
GENERATED_HEADER = re.compile(r"^// Code generated .* DO NOT EDIT\.$")


def is_generated(data):
    """True when the file's leading comment lines include the generated-code header."""
    for raw in data.decode("utf-8", "replace").splitlines():
        line = raw.strip()
        if not line:
            continue
        if not line.startswith("//"):
            return False
        if GENERATED_HEADER.match(line):
            return True
    return False


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


# The reviewed per-repo allowlist. Callers read it from the base side of a change (the PR
# base, the commit before a push, the remote's default branch), never from the commits under
# test, so an entry only counts once its own PR is merged. `ai-tell` entries are for the
# local pre-push gate's AI-tell layer; this scanner accepts them and never uses them.
ALLOW_FILE = ".github/scrub-allow.txt"
ALLOW_FILE_CLASSES = CLASSES + ("ai-tell",)
ALLOW_VALUE = re.compile(r"(?:[^%*?\[\]\s#]|%[0-9A-Fa-f]{2})+")
ALLOW_GLOB = re.compile(r"[^\s#]+")


@dataclass
class AllowEntry:
    cls: str
    value: str
    glob: str
    line: int
    written: str
    label: str = ""


def parse_allow_line(text):
    """(class, value, glob, reason) for an entry line, None for a blank or comment line.

    Raises ValueError for anything else. The value is percent-decoded (%20 for a space).
    """
    body, sep, reason = text.rstrip("\r").partition("#")
    fields = body.split()
    if not fields:
        return None
    if len(fields) != 3:
        raise ValueError("want '<class> <value> <path glob>  # reason'")
    cls, value, glob = fields
    if cls == "secret":
        raise ValueError("secrets can't be allowed here; put scrub:allow=secret on the line")
    if cls not in ALLOW_FILE_CLASSES:
        raise ValueError(f"unknown class '{cls}' (one of {', '.join(ALLOW_FILE_CLASSES)})")
    if not ALLOW_VALUE.fullmatch(value):
        raise ValueError("the value must be exact: no wildcards, and % only as a %XX escape")
    if (not ALLOW_GLOB.fullmatch(glob) or glob.startswith("/") or ".." in glob.split("/")
            or not re.search(r"[^*?/]", glob)):
        raise ValueError("the path glob must be relative and name more than wildcards")
    value = re.sub(r"%([0-9A-Fa-f]{2})", lambda m: chr(int(m.group(1), 16)), value)
    return cls, value, glob, reason.strip() if sep else ""


class AllowList:
    """Entries of a reviewed allowlist file; each allows one exact value in matching paths."""

    def __init__(self, entries=()):
        self.entries = list(entries)

    def match(self, cls, value, path):
        for e in self.entries:
            if e.cls == cls and e.value == value and fnmatch.fnmatchcase(path, e.glob):
                return e
        return None

    def allow(self, f):
        """Allow a finding on a file line (never a message, path or binary run) if listed."""
        if f.allowed_by or not f.file or not f.line:
            return False
        e = self.match(f.cls, f.match, f.file)
        if e:
            f.allowed_by = e.label
        return bool(e)


def parse_allowlist(text, label=ALLOW_FILE):
    """An AllowList from the file's text. Any malformed line raises ValueError naming it.

    One entry per line, `<class> <value> <path glob>`, with a `# reason` on the same line or
    on a comment line directly above it.
    """
    entries, reason_above = [], False
    for n, raw in enumerate(text.split("\n"), 1):
        stripped = raw.strip()
        if stripped.startswith("#"):
            reason_above = bool(stripped.lstrip("#").strip())
            continue
        try:
            parsed = parse_allow_line(raw)
        except ValueError as e:
            raise ValueError(f"{label}:{n}: {e}")
        if parsed is None:
            reason_above = False
            continue
        cls, value, glob, reason = parsed
        if not reason and not reason_above:
            raise ValueError(f"{label}:{n}: needs a # reason on the line or the line above")
        written = " ".join(raw.partition("#")[0].split())
        entries.append(AllowEntry(cls, value, glob, n, written, f"{label}:{n} ({written})"))
        reason_above = False
    return AllowList(entries)


def load_allowlist(path, label=ALLOW_FILE):
    with open(path, encoding="utf-8") as fh:
        return parse_allowlist(fh.read(), label)


def is_code_selector(labels):
    if len(labels) != 2:
        return False
    first, last = labels
    return (len(first) == 1 or first.lower() in CODE_RECEIVERS
            or (first.islower() and last.istitle()))


class Scanner:
    def __init__(self, allowed_domains=()):
        self.allowed = (PUBLIC_DOMAINS | ORG_DOMAINS
                        | {d.lower().strip(".") for d in allowed_domains if d})

    def domain_allowed(self, host):
        host = host.lower().rstrip(".")
        if EXAMPLE_DOMAIN.search(host):
            return True
        return any(host == d or host.endswith("." + d) for d in self.allowed)

    def email_allowed(self, local, domain):
        domain = domain.lower()
        return bool(EMAIL_EXAMPLE_DOMAIN.search(domain) or domain in EMAIL_ALLOWED_DOMAINS
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
            if not self.domain_allowed(host) and not self.descriptor_glue(text, m.start(1), host):
                found.append(Finding("fqdn", host))
        return found

    def descriptor_glue(self, text, start, host):
        """True when host is an allowed domain behind protobuf bytes in a raw descriptor.

        protoc-gen-go writes descriptors as Go string literals, so a string
        field's tag and length bytes can print as letters glued onto the value
        (go_package: "Z" then the length), inside an options message's own tag
        and length ("B" then the length). Strip up to four layers of a tag byte,
        a length byte that fits the literal, and \\xNN escapes; the rest must be
        an allowed domain, so nothing that isn't allowed ever passes.
        """
        rest = host
        for _ in range(4):
            if start > 0 and text[start - 1] == "\\" and re.match(r"x[0-9a-f]{2}", rest, re.I):
                rest, start = rest[3:], start + 3
            else:
                k = self._length_prefix(text, start, rest)
                if not k:
                    return False
                rest, start = rest[k:], start + k
            if self.domain_allowed(rest):
                return True
        return False

    @staticmethod
    def _length_prefix(text, start, rest):
        """How many glued bytes (1 or 2: a length, or a tag and a length) lead rest, or 0."""
        for k in (2, 1):
            if len(rest) <= k:
                continue
            if k == 2 and (ord(rest[0]) & 7 != 2 or ord(rest[0]) < 8):
                continue
            n = ord(rest[k - 1])
            value = text[start + k:start + k + n]
            if len(value) == n and '"' not in value and value.lower().startswith(rest[k:].lower()):
                return k
        return 0

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


def lines(text):
    """Split on "\n" only. str.splitlines() also breaks on \r, \x0c, \x1c-\x1e,
    \x85 and U+2028/2029, and the text after one of those on an added diff line
    would then never be scanned."""
    return text.split("\n")


def show_path(path):
    """A path as it's safe to print on one line."""
    return (path.replace("\\", "\\\\").replace("\n", "\\n").replace("\r", "\\r")
            .replace("\t", "\\t"))


DIFF_OPTS = ("--text", "--no-color", "--no-ext-diff", "--no-textconv", "--unified=0")


def changed_files(base, head):
    """(old mode, new mode, old blob, new blob, status, path) per file, from -z plumbing."""
    parts = git_bytes("diff-tree", "-r", "-z", "--no-renames", "--raw", base, head).split(b"\0")
    out = []
    for i in range(0, len(parts) - 1, 2):
        old_mode, new_mode, old_sha, new_sha, status = parts[i].decode("ascii")[1:].split()
        out.append((old_mode, new_mode, old_sha, new_sha, status,
                    parts[i + 1].decode("utf-8", "replace")))
    return out


def added_lines(old_mode, old_sha, new_sha, data):
    """(line number, text) of every line the new blob adds over the old one."""
    if old_mode in ("000000", "160000"):
        text = lines(data.decode("utf-8", "replace"))
        if text and text[-1] == "":
            text.pop()
        return list(enumerate(text, 1))
    out, in_hunk, lineno = [], False, 0
    for raw in lines(git("diff", *DIFF_OPTS, old_sha, new_sha)):
        if raw.startswith("@@"):
            in_hunk = True
            m = re.match(r"@@ -\S+ \+(\d+)", raw)
            lineno = int(m.group(1)) if m else 0
        elif in_hunk and raw.startswith("+"):
            out.append((lineno, raw[1:]))
            lineno += 1
    return out


class Collector:
    """Collects findings, dropping repeats of the same class and match in a file."""

    def __init__(self, scanner, allowlist=None):
        self.scanner = scanner
        self.allowlist = allowlist or AllowList()
        self.findings = []
        self.seen = set()

    def add(self, text, where, file="", line=0, generated=False, **kw):
        # CRLF content (PR bodies from GitHub, Windows files): drop the line's own \r.
        text = text.removesuffix("\r")
        found = self.scanner.line(text, **kw)
        if generated:
            for f in found:
                if f.cls == "fqdn" and not f.allowed_by:
                    f.allowed_by = "generated code"
        if file and line and kw.get("honor_allow", True):
            self.allow_listed(found, text, file, line)
        for f in found:
            key = (file or where, f.cls, f.match, f.allowed_by)
            if key in self.seen:
                continue
            self.seen.add(key)
            f.where, f.file, f.line = where, file, line
            self.findings.append(f)

    def allow_listed(self, found, text, file, line):
        """Apply the allowlist to findings on one file line.

        A line of the allowlist file itself that is a well-formed entry also allows its own
        value, for its own class, on that line: the entry is what the PR asks reviewers to
        accept. Anything else on the line, its reason included, is still scanned.
        """
        own = None
        if file == ALLOW_FILE:
            try:
                own = parse_allow_line(text)
            except ValueError:
                own = None
        for f in found:
            if f.allowed_by:
                continue
            f.file, f.line = file, line
            if not self.allowlist.allow(f) and own and (f.cls, f.match) == own[:2]:
                f.allowed_by = f"{ALLOW_FILE} entry itself"

    def changes(self, base, head, label):
        """Scan the paths and added content of every file changed from base to head."""
        for old_mode, new_mode, old_sha, new_sha, status, path in changed_files(base, head):
            if status == "D":
                continue
            shown, docs = show_path(path), docs_example_path(path)
            self.add(path, f"{shown} (path, {label})", path, honor_allow=False,
                     docs_example=docs)
            if new_mode == "160000":
                continue
            data = git_bytes("cat-file", "blob", new_sha, check=False)
            if data is None:
                sys.stderr.write(f"scrub: can't read the content of {shown} ({label})\n")
                sys.exit(2)
            if path.lower().endswith(ASSET_EXTENSIONS):
                m = PROVENANCE.search(data)
                if m:
                    self.provenance(path, f"{shown} (asset, {label})", m.group(0).decode("ascii"))
            if b"\x00" in data:
                if path.lower().endswith(FONT_EXTENSIONS):
                    continue
                # Compiled files, images and UTF-16 text: scan their string runs.
                for run in string_runs(data):
                    self.add(run, f"{shown} (binary, {label})", path, binary=True,
                             honor_allow=False, docs_example=docs)
                continue
            generated = is_generated(data)
            for lineno, text in added_lines(old_mode, old_sha, new_sha, data):
                self.add(text, f"{shown}:{lineno} ({label})", path, lineno,
                         generated=generated, docs_example=docs)

    def provenance(self, path, where, marker):
        key = (path, "provenance", marker, "")
        if key not in self.seen:
            self.seen.add(key)
            self.findings.append(Finding("provenance", marker, where, path))

    def message(self, sha):
        short = sha[:12]
        meta = git("show", "-s", "--format=%an%x00%ae%x00%cn%x00%ce%x00%B", sha).split("\x00", 4)
        an, ae, cn, ce, body = (meta + [""] * 5)[:5]
        self.add(f"{an} <{ae}>", f"commit {short} author", honor_allow=False)
        self.add(f"{cn} <{ce}>", f"commit {short} committer", honor_allow=False)
        for n, text in enumerate(lines(body.rstrip("\n")), 1):
            self.add(text, f"commit {short} commit message:{n}", honor_allow=False)

    def pr_text(self):
        for text in lines(os.environ.get("PR_TITLE", "")):
            self.add(text, "PR title", honor_allow=False)
        for n, text in enumerate(lines(os.environ.get("PR_BODY", "")), 1):
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
    try:
        if args.check_allow_file:
            load_allowlist(args.check_allow_file, args.allow_label)
        allowlist = load_allowlist(args.allow_file, args.allow_label) if args.allow_file else None
    except (OSError, ValueError) as e:
        print(f"scrub identifiers: allowlist: {e}", file=sys.stderr)
        return 2
    col = Collector(Scanner(domains), allowlist)
    empty_tree = git("hash-object", "-t", "tree", "/dev/null").strip()
    for sha in commits(args.base, args.head):
        parents = git("rev-list", "--parents", "-n1", sha).split()[1:]
        col.changes(parents[0] if parents else empty_tree, sha, f"commit {sha[:12]}")
    # The net diff catches what merge commits add (conflict resolutions included).
    base = git("merge-base", args.base, args.head).strip() if args.base else empty_tree
    col.changes(base, args.head, "net diff")
    for sha in commits(args.base, args.head, merges=True):
        col.message(sha)
    col.pr_text()
    return report("identifiers", col.findings, lambda f: f"{f.where}: {f.cls}: {f.match}")


DCO_EXEMPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dco-exempt.txt")
DCO_EXEMPT_LINE = re.compile(r"^([\w.-]+/[\w.-]+) ([0-9a-f]{40}) (\S.*)$")


def load_dco_exempt(path):
    """The reviewed list of default-branch commits that may lack a sign-off: {(repo, sha): reason}.

    One entry per line, `<owner>/<repo> <full sha> <reason>`; # starts a comment. Any other
    line is an error, so a typo or a short sha can't silently exempt the wrong commit.
    """
    entries = {}
    if not os.path.exists(path):
        return entries
    with open(path, encoding="utf-8") as fh:
        for number, raw in enumerate(fh, 1):
            text = raw.strip()
            if not text or text.startswith("#"):
                continue
            m = DCO_EXEMPT_LINE.match(text)
            if not m:
                raise ValueError(f"{path}:{number}: want '<owner>/<repo> <40-hex sha> <reason>'")
            entries[(m.group(1).lower(), m.group(2))] = m.group(3)
    return entries


def on_branch(sha, tip):
    return subprocess.run(["git", "merge-base", "--is-ancestor", sha, tip],
                          capture_output=True).returncode == 0


def cmd_dco(args):
    try:
        exempt = load_dco_exempt(args.exempt_file)
    except ValueError as e:
        print(f"scrub dco: {e}", file=sys.stderr)
        return 2
    repo = (args.repo or os.environ.get("GITHUB_REPOSITORY", "")).lower()
    findings = []
    for sha in commits(args.base, args.head):
        body = git("show", "-s", "--format=%B", sha)
        if not SIGNOFF.search(body):
            subject = lines(body)[0].removesuffix("\r")
            f = Finding("dco", subject, where=f"commit {sha[:12]}")
            reason = exempt.get((repo, sha))
            # Only a full scan of the default branch honours the list, and only for commits
            # already on it: a PR or a branch push never does, so new commits can't use it.
            if reason and args.default_branch_tip and not args.base and on_branch(sha, args.default_branch_tip):
                f.allowed_by = f"dco-exempt ({reason})"
            findings.append(f)
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
            p.add_argument("--allow-file", default="",
                           help=f"the reviewed allowlist ({ALLOW_FILE}) read from the base side")
            p.add_argument("--check-allow-file", default="",
                           help="an allowlist to check for errors without applying it")
            p.add_argument("--allow-label", default=ALLOW_FILE,
                           help="how warnings name the allowlist, e.g. its path at the base sha")
        else:
            p.add_argument("--exempt-file", default=DCO_EXEMPT,
                           help="the reviewed dco-exempt list (default: next to this script)")
            p.add_argument("--repo", default="", help="owner/repo; default $GITHUB_REPOSITORY")
            p.add_argument("--default-branch-tip", default="",
                           help="set only for a full scan of the default branch; enables the list")
    args = parser.parse_args(argv)
    return cmd_identifiers(args) if args.cmd == "identifiers" else cmd_dco(args)


if __name__ == "__main__":
    sys.exit(main())
