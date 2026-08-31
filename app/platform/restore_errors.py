"""One exception family for everything a restore can refuse.

These live in their own leaf module because three modules need them and none
of them may import each other: ``restore_service`` (the orchestration),
``restore_sources`` (reading a foreign panel) and ``admin_api`` (turning a
refusal into an HTTP answer).

That last one is why this file exists. A refusal raised in
``restore_sources`` was not a subclass of the ``RestoreError`` the endpoints
caught, so "I could not find a database in your archive" reached the operator
as a bare HTTP 500 — indistinguishable from a crash — instead of a message
telling them what to do about it. One base class fixes that for every
refusal, present and future.
"""
from __future__ import annotations


class RestoreError(RuntimeError):
    """Base class: the archive or the request cannot be honoured.

    Raising this (or a subclass) is how a restore says *no* in a way the API
    can explain to a human. Anything else is a bug and should be a 500.
    """


class RestoreSourceError(RestoreError):
    """The archive cannot be attributed to the selected panel."""


class RestoreFormatError(RestoreError):
    """The upload is not a shape we know how to open."""
