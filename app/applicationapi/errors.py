"""Low-information errors for the public Application API."""
from __future__ import annotations


class ApplicationApiError(Exception):
    status_code = 400
    error_code = "application_request_rejected"


class ApplicationAuthFailed(ApplicationApiError):
    status_code = 401
    error_code = "authentication_failed"


class ApplicationForbidden(ApplicationApiError):
    status_code = 403
    error_code = "application_access_denied"


class EnrollmentRequired(ApplicationApiError):
    status_code = 403
    error_code = "device_enrollment_required"


class ActivationTicketInvalid(ApplicationApiError):
    status_code = 401
    error_code = "activation_ticket_invalid"


class ActivationTicketExpired(ActivationTicketInvalid):
    status_code = 410
    error_code = "activation_ticket_expired"


class ReplayRejected(ApplicationApiError):
    status_code = 409
    error_code = "request_replay_rejected"


class ApplicationRateLimited(ApplicationApiError):
    status_code = 429
    error_code = "rate_limited"


class DeviceLimitReached(ApplicationApiError):
    status_code = 403
    error_code = "device_limit_reached"


class SecureTransportRequired(ApplicationApiError):
    status_code = 400
    error_code = "https_required"


class ConfigGrantExpired(ApplicationApiError):
    status_code = 410
    error_code = "config_grant_expired"


class ConfigGrantConsumed(ApplicationApiError):
    status_code = 409
    error_code = "config_grant_consumed"


class ConfigGrantInvalid(ApplicationApiError):
    status_code = 404
    error_code = "config_grant_invalid"


class ProtocolUnavailable(ApplicationApiError):
    status_code = 409
    error_code = "protocol_unavailable"


class ConnectionRequired(ApplicationApiError):
    status_code = 409
    error_code = "connection_required"


class ConnectionFailed(ApplicationApiError):
    status_code = 409
    error_code = "connection_failed"


class ConnectionNotFound(ApplicationApiError):
    status_code = 404
    error_code = "connection_not_found"


class DeviceNotFound(ApplicationApiError):
    status_code = 404
    error_code = "device_not_found"


class ApplicationNotFound(ApplicationApiError):
    status_code = 404
    error_code = "application_not_found"


class ApplicationGrantNotFound(ApplicationApiError):
    status_code = 404
    error_code = "application_grant_not_found"


class ApplicationKeyNotFound(ApplicationApiError):
    status_code = 404
    error_code = "application_key_not_found"
