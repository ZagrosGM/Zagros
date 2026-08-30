"""Upstream release discovery for cores that ship from GitHub releases.

Both halves of the panel need the same thing — "which versions of this core
exist?" — the master for its own installs, and the node view for a core that
is installed on a node. The node's drivers are a vendored copy of these ones,
so the answer is the same list either way; what differs is only *who asks*.

Kept in one place so the caching, the "this core has no release feed" case and
the error messages cannot drift apart between the two routes.
"""
from __future__ import annotations

import asyncio
import time

from app.cores.registry import available_drivers, get_driver_class

# Release lists change rarely (a new core release every few weeks) and every
# lookup is a network call, so they are cached per core for a short while.
_CACHE: dict[str, tuple[float, list[dict]]] = {}
_TTL_SECONDS = 600.0


def clear_cache() -> None:
    """Forget every cached release list (tests, and after a forced refresh)."""
    _CACHE.clear()


class NoReleaseFeed(Exception):
    """The core has no upstream release list (it is installed by the OS)."""


def release_repo(core_id: str) -> str:
    """The GitHub repo a core's binaries come from, or '' when none."""
    if core_id not in available_drivers():
        raise KeyError(core_id)
    return get_driver_class(core_id).metadata.release_repo or ""


async def recent_releases(core_id: str, limit: int = 10) -> dict:
    """Recent upstream release tags for one core, newest first.

    Raises :class:`KeyError` for an unknown core and :class:`NoReleaseFeed`
    for a core the OS installs instead — both are 404s at the API boundary,
    but they need different words attached to them.
    """
    repo = release_repo(core_id)          # KeyError for an unknown core
    if not repo:
        raise NoReleaseFeed(
            f"core '{core_id}' is not GitHub-release managed — no version "
            "list is available (install uses the OS package)")

    now = time.monotonic()
    cached = _CACHE.get(core_id)
    if cached and now - cached[0] < _TTL_SECONDS:
        releases = cached[1]
    else:
        from app.cores.github_install import fetch_recent_releases

        releases = await asyncio.to_thread(
            fetch_recent_releases, repo, limit=limit)
        _CACHE[core_id] = (now, releases)
    return {"core": core_id, "repo": repo,
            "releases": releases[: max(1, min(limit, 30))]}
