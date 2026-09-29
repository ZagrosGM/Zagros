"""Low-information errors for the white-label build system."""
from __future__ import annotations


class BuildError(Exception):
    status_code = 400
    error_code = "build_request_rejected"


class BuildNotFound(BuildError):
    status_code = 404
    error_code = "build_not_found"


class BuildForbidden(BuildError):
    status_code = 403
    error_code = "build_access_denied"


class BuildValidationFailed(BuildError):
    status_code = 422
    error_code = "build_invalid"


class BuildConflict(BuildError):
    status_code = 409
    error_code = "build_conflict"


class BuildQueueUnavailable(BuildError):
    status_code = 503
    error_code = "build_queue_unavailable"


class WorkerAuthFailed(BuildError):
    status_code = 401
    error_code = "worker_authentication_failed"


class WorkerNotFound(BuildError):
    status_code = 404
    error_code = "worker_not_found"


class WorkerConflict(BuildError):
    status_code = 409
    error_code = "worker_conflict"


class CredentialNotFound(BuildError):
    status_code = 404
    error_code = "build_credential_not_found"


class CredentialRevoked(BuildError):
    status_code = 409
    error_code = "build_credential_revoked"
