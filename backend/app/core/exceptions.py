"""
SentinelGraph — Custom Exceptions

Structured exception hierarchy for consistent error handling.
All exceptions map to HTTP status codes and include error codes
for machine-readable error identification.
"""

from typing import Any


class SentinelGraphError(Exception):
    """Base exception for all SentinelGraph errors."""

    status_code: int = 500
    error_code: str = "INTERNAL_ERROR"
    detail: str = "An unexpected error occurred"

    def __init__(
        self,
        detail: str | None = None,
        error_code: str | None = None,
        context: dict[str, Any] | None = None,
    ):
        self.detail = detail or self.__class__.detail
        self.error_code = error_code or self.__class__.error_code
        self.context = context or {}
        super().__init__(self.detail)

    def to_dict(self) -> dict[str, Any]:
        return {
            "error": {
                "code": self.error_code,
                "message": self.detail,
                "context": self.context,
            }
        }


# ── Authentication Errors ────────────────────────────────────
class AuthenticationError(SentinelGraphError):
    status_code = 401
    error_code = "AUTHENTICATION_REQUIRED"
    detail = "Authentication is required"


class InvalidCredentialsError(AuthenticationError):
    error_code = "INVALID_CREDENTIALS"
    detail = "Invalid email or password"


class TokenExpiredError(AuthenticationError):
    error_code = "TOKEN_EXPIRED"
    detail = "Token has expired"


class InvalidTokenError(AuthenticationError):
    error_code = "INVALID_TOKEN"
    detail = "Token is invalid or malformed"


# ── Authorization Errors ────────────────────────────────────
class AuthorizationError(SentinelGraphError):
    status_code = 403
    error_code = "FORBIDDEN"
    detail = "You do not have permission to perform this action"


class InsufficientRoleError(AuthorizationError):
    error_code = "INSUFFICIENT_ROLE"
    detail = "Your role does not have sufficient permissions"


# ── Scope Enforcement Errors ────────────────────────────────
class ScopeViolationError(SentinelGraphError):
    """Raised when a request targets resources outside authorized scope."""

    status_code = 403
    error_code = "SCOPE_VIOLATION"
    detail = "Request target is outside authorized scope boundaries"


class ScopeNotFoundError(SentinelGraphError):
    status_code = 404
    error_code = "SCOPE_NOT_FOUND"
    detail = "Authorized scope not found"


class ScopeValidationError(SentinelGraphError):
    status_code = 422
    error_code = "SCOPE_VALIDATION_FAILED"
    detail = "Scope validation failed"


class DNSRebindingError(ScopeViolationError):
    error_code = "DNS_REBINDING_DETECTED"
    detail = "Potential DNS rebinding attack detected"


class PrivateIPError(ScopeViolationError):
    error_code = "PRIVATE_IP_BLOCKED"
    detail = "Request targets a private/internal IP address (SSRF protection)"


# ── Resource Errors ──────────────────────────────────────────
class NotFoundError(SentinelGraphError):
    status_code = 404
    error_code = "NOT_FOUND"
    detail = "Resource not found"


class ConflictError(SentinelGraphError):
    status_code = 409
    error_code = "CONFLICT"
    detail = "Resource already exists"


class ValidationError(SentinelGraphError):
    status_code = 422
    error_code = "VALIDATION_ERROR"
    detail = "Request validation failed"


# ── Scan Errors ──────────────────────────────────────────────
class ScanError(SentinelGraphError):
    status_code = 500
    error_code = "SCAN_ERROR"
    detail = "Scan execution failed"


class ScanNotFoundError(NotFoundError):
    error_code = "SCAN_NOT_FOUND"
    detail = "Scan not found"


class ScanAlreadyRunningError(ConflictError):
    error_code = "SCAN_ALREADY_RUNNING"
    detail = "A scan is already running for this target"


class ScanCancelledError(ScanError):
    status_code = 400
    error_code = "SCAN_CANCELLED"
    detail = "Scan was cancelled"


# ── Rate Limiting ────────────────────────────────────────────
class RateLimitExceededError(SentinelGraphError):
    status_code = 429
    error_code = "RATE_LIMIT_EXCEEDED"
    detail = "Too many requests. Please try again later."


# ── AI/LLM Errors ───────────────────────────────────────────
class AIAnalysisError(SentinelGraphError):
    status_code = 502
    error_code = "AI_ANALYSIS_FAILED"
    detail = "AI analysis failed"


class LLMTimeoutError(AIAnalysisError):
    error_code = "LLM_TIMEOUT"
    detail = "LLM request timed out"


class LLMOutputValidationError(AIAnalysisError):
    error_code = "LLM_OUTPUT_INVALID"
    detail = "LLM output failed validation"
