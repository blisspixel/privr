# Systemd storage configuration evidence

Design recorded 2026-10-11 for issue 18, before implementation.

The coredump and journald controls must never infer loaded state from files.
Both return Unknown, including when configured intent matches or opposes the
selected policy. Their existing result note carries a bounded explanation;
control IDs, profiles, risk metadata, report schema and the pure engine stay
unchanged. CLI checks are incomplete (exit 3); successful MCP checks retain
`isError: false`. MCP explain retains its existing schema and null state;
the full check and CLI explanation carry the configuration note.

The Linux Reader owns two compiled configuration families and four compiled
roots, in priority order: `/etc/systemd`, `/run/systemd`,
`/usr/local/lib/systemd`, `/usr/lib/systemd`. Recorded raw observations never
fall back to live reads. Select the first present main file. Enumerate every
drop-in directory, select the highest-priority copy of each basename, then
parse winners lexically after the main file. Empty regular files shadow lower
copies. Only regular files and exact `/dev/null` masking links are admitted.
Recheck file metadata and directory listings; observed changes refuse a
conclusion, without claiming an atomic snapshot.

Bounds are 64 KiB per file, 512 KiB per family, 64 drop-in entries across all
roots, 255 bytes per basename and 4 KiB per line. Reject unsafe names, unexpected
types, denied or omitted observations, invalid UTF-8, NUL and unsupported
syntax. Never truncate or echo local paths, basenames or raw invalid values.
Parse exact sections `[Coredump]` and `[Journal]`, exact `Storage` keys,
whitespace around `=`, full-line comments, CRLF and repeated sections. The
last recognized scalar wins. Invalid relevant assignments and unsupported
continuations taint the entire interpretation. No assignment means unspecified,
not an observed default. No command, service query or additional host probe is
introduced.

This interpretation describes systemd v262 standard-path configured intent.
Older builds can use a different main-file layout, including v255's compiled
main path. The running version, build, loaded generation, credentials, command
line, namespace and instance are unverified. Coredump `Storage=none` concerns
permanent retention, not temporary writes or backtraces. Journald `auto` does
not establish persistent storage; directory existence would not attest it.
Neither `none` nor `volatile` proves forwarding disabled or existing logs gone.

Primary references: [v262 coredump configuration](https://github.com/systemd/systemd/blob/v262/man/coredump.conf.xml),
[v262 journald configuration](https://github.com/systemd/systemd/blob/v262/man/journald.conf.xml),
[v262 configuration parser](https://github.com/systemd/systemd/blob/v262/src/shared/conf-parser.c),
[v255 configuration parser](https://github.com/systemd/systemd/blob/v255/src/shared/conf-parser.c).

Verification starts with actual compiled-control false-pass regressions, then
raw precedence, masking, parser, failure and bound controls. Context, report,
CLI and MCP tests use recorded evidence. Other compiled controls still prove
legitimate Pass and Drift. All repository gates and offline binary smokes are
required before delivery; real-desktop runtime validation remains unclaimed.
