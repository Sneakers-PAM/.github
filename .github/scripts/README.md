# Scrub 1 tools

`scrub.py` holds the generic identifier and DCO checks behind the org's reusable workflow,
`.github/workflows/scrub.yml`. It reads no term list: every pattern is generic.

## Run it locally

```bash
python3 .github/scripts/scrub.py identifiers --base origin/main --head HEAD
python3 .github/scripts/scrub.py dco --base origin/main --head HEAD
python3 .github/scripts/scrub_test.py
```

Leave out `--base` to scan the whole history.

## What it checks

- **identifiers** flags `private-ip`, `email`, `home-path` and `fqdn` matches. It reads:
  - each non-merge commit's added lines, plus the net `base...head` diff (which covers merges);
  - the touched paths;
  - every commit message, author and committer, merges included;
  - the PR title and body.

  Diffs always run with `--text`, so `.gitattributes` can't hide a file. A file whose content has
  a NUL byte is treated as binary, and its ASCII, UTF-16LE and UTF-16BE string runs are scanned.
- **dco** requires `Signed-off-by: Name <email>` on every non-merge commit.

## Allowing a match

- `scrub:allow=<class>[,<class>]` on a line of a file allows those classes on that line only, for
  example `# scrub:allow=private-ip`. A bare `scrub:allow` allows nothing.
- Markers are never honoured in commit messages, author lines, paths or PR text.
- Files under the top-level `docs/examples/` may hold private addresses; every other check still
  applies there.
- The RFC 5737 and RFC 3849 documentation ranges, example.* domains, GitHub noreply addresses and
  the built-in public domains always pass. Callers add their own domain with the workflow's
  `allowed-domains` input.

Every honoured allow is reported as a warning, both in the log and in the job summary.

## Limits

Compressed content isn't unpacked: zip, docx/xlsx, jar, gz and tar.gz, PNG zTXt/iTXt chunks, PDF
streams and the like. Scrub 2, the independent reviewer pass, reviews those files.
Scrub 1 is a pattern check; it doesn't catch names, short host names, ticket keys or codenames.
Scrub 2 does that too.
