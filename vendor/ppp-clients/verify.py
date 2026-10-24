"""Verify the installed PPP/IPsec client packages against the pinned manifest.

Called from the Dockerfile with the target Debian architecture, so one image
recipe serves every published platform (f-multiarch-1). Previously the recipe
hard-failed on anything but amd64 (`test "$(dpkg --print-architecture)" =
"amd64"`), which is why the panel image — and therefore `zagros install` —
could never run on an arm64 VPS.

Usage:  python3 verify.py <debian-arch> [manifest-path]
        python3 verify.py --emit-urls <debian-arch> [manifest-path]
Exit:   0 = every pinned package is installed at the pinned version
        1 = at least one mismatch (printed on stderr)

``--emit-urls`` prints ``<url> <sha256> <filename>`` per pinned package so the
Dockerfile can fetch and verify them with plain curl + sha256sum.
"""
from __future__ import annotations

import json
import subprocess
import sys


def installed_version(package: str) -> str | None:
    try:
        return subprocess.run(
            ["dpkg-query", "-W", "-f=${Version}", package],
            capture_output=True, text=True, check=True,
        ).stdout.strip() or None
    except subprocess.CalledProcessError:
        return None


def main(argv: list[str]) -> int:
    emit = "--emit-urls" in argv
    rest = [item for item in argv[1:] if item != "--emit-urls"]
    arch = rest[0] if rest else ""
    manifest_path = rest[1] if len(rest) > 1 else "/tmp/ppp-client-manifest.json"
    with open(manifest_path, encoding="utf-8") as handle:
        manifest = json.load(handle)
    arches = manifest.get("arches") or {}
    if arch not in arches:
        print(
            f"no pinned PPP client packages for architecture '{arch}' "
            f"(manifest has: {', '.join(sorted(arches)) or 'none'})",
            file=sys.stderr,
        )
        return 1
    if emit:
        for entry in arches[arch]["packages"]:
            print(f"{entry['url']} {entry['sha256']} {entry['filename']}")
        return 0
    problems: list[str] = []
    for entry in arches[arch]["packages"]:
        found = installed_version(entry["package"])
        if found is None:
            problems.append(f"{entry['package']}: not installed")
        elif found != entry["version"]:
            problems.append(
                f"{entry['package']}: installed {found} != pinned {entry['version']}")
    if problems:
        print("PPP client manifest verification failed:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1
    print(f"PPP client packages verified for {arch} "
          f"({len(arches[arch]['packages'])} packages)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
