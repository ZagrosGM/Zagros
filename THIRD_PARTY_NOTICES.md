# Third-party notices

## ACCEL-PPP 1.14.0

The optional, default-disabled independent PPTP provider executes ACCEL-PPP as
a separate process.

- Project: https://github.com/accel-ppp/accel-ppp
- Version: 1.14.0
- Commit: `048d31cb446879e0d1a1471b4ab99135a92bf289`
- License: GNU General Public License, version 2 only
- Source and checksum: `vendor/accel-ppp/manifest.json`

The container includes the exact corresponding source archive, its manifest,
and the upstream `COPYING` file under
`/usr/share/doc/zagros/accel-ppp-1.14.0/`.

ACCEL-PPP is not linked into Zagros. It is invoked as an independent daemon and
communicates through a loopback management socket and provider-owned files.
