"""
SentinelGraph — Scope Enforcement Gateway

P0 CRITICAL: Every outbound request from any scanner engine MUST pass through
this gateway. It validates that targets are within authorized scope boundaries,
blocks private IPs (SSRF protection), detects DNS rebinding, and enforces
rate limits. Every decision is audit-logged.
"""

import ipaddress
import socket
import time
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlparse

import structlog

from app.core.exceptions import (
    DNSRebindingError,
    PrivateIPError,
    RateLimitExceededError,
    ScopeViolationError,
)
from app.core.redis import RateLimiter, RedisCache
from app.models.scope import AuthorizedScope, ScopeStatus, ScopeType

logger = structlog.get_logger(__name__)


class ValidationDecision(str, Enum):
    """Gateway decision outcome."""

    ALLOW = "allow"
    DENY = "deny"


@dataclass
class ValidationResult:
    """Result of a scope enforcement check."""

    decision: ValidationDecision
    reason: str
    scope_id: str | None = None
    resolved_ip: str | None = None
    checks_passed: list[str] = field(default_factory=list)
    checks_failed: list[str] = field(default_factory=list)
    elapsed_ms: float = 0.0


# ── Private/Reserved IP Ranges ───────────────────────────────
PRIVATE_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),        # "This" network
    ipaddress.ip_network("10.0.0.0/8"),        # Private (Class A)
    ipaddress.ip_network("100.64.0.0/10"),     # Carrier-grade NAT
    ipaddress.ip_network("127.0.0.0/8"),       # Loopback
    ipaddress.ip_network("169.254.0.0/16"),    # Link-local
    ipaddress.ip_network("172.16.0.0/12"),     # Private (Class B)
    ipaddress.ip_network("192.0.0.0/24"),      # IETF protocol assignments
    ipaddress.ip_network("192.0.2.0/24"),      # TEST-NET-1
    ipaddress.ip_network("192.168.0.0/16"),    # Private (Class C)
    ipaddress.ip_network("198.18.0.0/15"),     # Network benchmark
    ipaddress.ip_network("198.51.100.0/24"),   # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),    # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),       # Multicast
    ipaddress.ip_network("240.0.0.0/4"),       # Reserved
    ipaddress.ip_network("255.255.255.255/32"),# Broadcast
]

PRIVATE_NETWORKS_V6 = [
    ipaddress.ip_network("::1/128"),           # Loopback
    ipaddress.ip_network("::/128"),            # Unspecified
    ipaddress.ip_network("fc00::/7"),          # Unique local
    ipaddress.ip_network("fe80::/10"),         # Link-local
    ipaddress.ip_network("ff00::/8"),          # Multicast
]


class ScopeEnforcementGateway:
    """
    Central security boundary for all outbound scanner requests.

    EVERY request to ANY external target MUST pass through validate_request().
    No exceptions. No bypasses. Violations are audit-logged and blocked.
    """

    def __init__(self):
        self.rate_limiter = RateLimiter(prefix="scope_ratelimit")
        self.dns_cache = RedisCache(prefix="dns_cache")
        self._audit_cache = RedisCache(prefix="scope_audit")

    async def validate_request(
        self,
        url: str,
        scope: AuthorizedScope,
    ) -> ValidationResult:
        """Validate a request against authorized scope.

        This is the ONLY entry point for outbound requests.
        All scanner engines must call this before making any HTTP request.

        Args:
            url: The target URL to validate
            scope: The authorized scope to validate against

        Returns:
            ValidationResult with ALLOW or DENY decision

        Raises:
            ScopeViolationError: If target is outside scope
            PrivateIPError: If target resolves to private IP
            DNSRebindingError: If DNS rebinding detected
            RateLimitExceededError: If rate limit exceeded
        """
        start_time = time.monotonic()
        checks_passed: list[str] = []
        checks_failed: list[str] = []

        try:
            # ── Check 1: Scope is active ────────────────────
            if scope.status != ScopeStatus.ACTIVE:
                checks_failed.append("scope_status")
                result = ValidationResult(
                    decision=ValidationDecision.DENY,
                    reason=f"Scope is not active (status: {scope.status.value})",
                    scope_id=str(scope.id),
                    checks_passed=checks_passed,
                    checks_failed=checks_failed,
                )
                await self._audit_log(url, scope, result)
                raise ScopeViolationError(
                    detail=f"Scope is {scope.status.value}, not active",
                    context={"scope_id": str(scope.id)},
                )
            checks_passed.append("scope_active")

            # ── Check 2: URL parsing & domain matching ──────
            parsed = urlparse(url)
            hostname = parsed.hostname
            if not hostname:
                checks_failed.append("url_parse")
                raise ScopeViolationError(
                    detail="Could not parse hostname from URL",
                    context={"url": url},
                )

            if not self._domain_matches_scope(hostname, scope):
                checks_failed.append("domain_match")
                result = ValidationResult(
                    decision=ValidationDecision.DENY,
                    reason=f"Domain {hostname} not in scope {scope.target}",
                    scope_id=str(scope.id),
                    checks_passed=checks_passed,
                    checks_failed=checks_failed,
                )
                await self._audit_log(url, scope, result)
                raise ScopeViolationError(
                    detail=f"Domain '{hostname}' is outside authorized scope '{scope.target}'",
                    context={"domain": hostname, "scope_target": scope.target},
                )
            checks_passed.append("domain_match")

            # ── Check 3: Path exclusions ────────────────────
            if scope.excluded_paths:
                path = parsed.path or "/"
                if self._path_is_excluded(path, scope.excluded_paths):
                    checks_failed.append("path_exclusion")
                    raise ScopeViolationError(
                        detail=f"Path '{path}' is excluded from scope",
                        context={"path": path},
                    )
            checks_passed.append("path_check")

            # ── Check 4: DNS resolution & private IP check ──
            resolved_ip = await self._resolve_and_validate_ip(hostname, scope)
            checks_passed.append("ip_validation")

            # ── Check 5: DNS rebinding protection ───────────
            await self._check_dns_rebinding(hostname, resolved_ip)
            checks_passed.append("dns_rebinding")

            # ── Check 6: Rate limiting ──────────────────────
            is_allowed, remaining = await self.rate_limiter.is_allowed(
                identifier=str(scope.id),
                max_requests=scope.max_requests_per_second,
                window_seconds=1,
            )
            if not is_allowed:
                checks_failed.append("rate_limit")
                raise RateLimitExceededError(
                    detail=f"Rate limit exceeded for scope ({scope.max_requests_per_second} req/s)",
                    context={"remaining": remaining},
                )
            checks_passed.append("rate_limit")

            # ── All checks passed ───────────────────────────
            elapsed = (time.monotonic() - start_time) * 1000
            result = ValidationResult(
                decision=ValidationDecision.ALLOW,
                reason="All scope checks passed",
                scope_id=str(scope.id),
                resolved_ip=resolved_ip,
                checks_passed=checks_passed,
                checks_failed=checks_failed,
                elapsed_ms=elapsed,
            )

            await self._audit_log(url, scope, result)
            return result

        except (ScopeViolationError, PrivateIPError, DNSRebindingError, RateLimitExceededError):
            raise
        except Exception as e:
            logger.error(
                "scope_gateway.unexpected_error",
                url=url,
                scope_id=str(scope.id),
                error=str(e),
            )
            raise ScopeViolationError(
                detail="Scope validation failed due to an internal error",
                context={"error": str(e)},
            )

    # ── Domain Matching ──────────────────────────────────────
    def _domain_matches_scope(
        self,
        hostname: str,
        scope: AuthorizedScope,
    ) -> bool:
        """Check if hostname falls within the authorized scope."""
        hostname = hostname.lower().strip(".")
        target = scope.target.lower().strip(".")

        if scope.scope_type == ScopeType.DOMAIN:
            if scope.include_subdomains:
                return hostname == target or hostname.endswith(f".{target}")
            return hostname == target

        elif scope.scope_type == ScopeType.WILDCARD:
            # Wildcard: *.example.com matches sub.example.com but NOT example.com
            base_domain = target.lstrip("*.")
            return hostname.endswith(f".{base_domain}") or hostname == base_domain

        elif scope.scope_type == ScopeType.URL_PREFIX:
            parsed_target = urlparse(target)
            return hostname == (parsed_target.hostname or "").lower()

        elif scope.scope_type == ScopeType.IP_RANGE:
            try:
                ip = ipaddress.ip_address(hostname)
                network = ipaddress.ip_network(target, strict=False)
                return ip in network
            except ValueError:
                return False

        return False

    # ── Path Exclusion ───────────────────────────────────────
    @staticmethod
    def _path_is_excluded(path: str, excluded_paths: list[str]) -> bool:
        """Check if a path matches any exclusion pattern."""
        import fnmatch

        for pattern in excluded_paths:
            if fnmatch.fnmatch(path, pattern):
                return True
        return False

    # ── IP Validation ────────────────────────────────────────
    async def _resolve_and_validate_ip(
        self,
        hostname: str,
        scope: AuthorizedScope,
    ) -> str:
        """Resolve hostname to IP and validate it's not private/internal.

        This is critical SSRF protection — prevents scanning internal networks.
        """
        try:
            # Check DNS cache first
            cached_ip = await self.dns_cache.get(f"resolve:{hostname}")
            if cached_ip:
                ip_str = cached_ip
            else:
                # Resolve DNS
                infos = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC)
                if not infos:
                    raise ScopeViolationError(
                        detail=f"Could not resolve hostname: {hostname}"
                    )
                ip_str = infos[0][4][0]

                # Cache with 60s TTL
                await self.dns_cache.set(f"resolve:{hostname}", ip_str, ttl_seconds=60)

        except socket.gaierror as e:
            raise ScopeViolationError(
                detail=f"DNS resolution failed for {hostname}: {e}",
                context={"hostname": hostname},
            )

        # Check against IP allowlist (takes priority)
        if scope.ip_allowlist:
            if ip_str in scope.ip_allowlist:
                return ip_str

        # Check against IP blocklist
        if scope.ip_blocklist and ip_str in scope.ip_blocklist:
            raise ScopeViolationError(
                detail=f"IP {ip_str} is in scope blocklist",
                context={"ip": ip_str},
            )

        # Check against private/reserved ranges
        if self._is_private_ip(ip_str):
            raise PrivateIPError(
                detail=f"Target resolves to private IP {ip_str} — blocked for SSRF protection",
                context={"hostname": hostname, "ip": ip_str},
            )

        return ip_str

    @staticmethod
    def _is_private_ip(ip_str: str) -> bool:
        """Check if an IP address is in a private/reserved range."""
        try:
            ip = ipaddress.ip_address(ip_str)

            if isinstance(ip, ipaddress.IPv4Address):
                return any(ip in net for net in PRIVATE_NETWORKS)
            elif isinstance(ip, ipaddress.IPv6Address):
                # Check for IPv4-mapped IPv6
                if ip.ipv4_mapped:
                    return any(ip.ipv4_mapped in net for net in PRIVATE_NETWORKS)
                return any(ip in net for net in PRIVATE_NETWORKS_V6)

        except ValueError:
            return True  # If we can't parse it, block it

        return False

    # ── DNS Rebinding Protection ─────────────────────────────
    async def _check_dns_rebinding(
        self,
        hostname: str,
        current_ip: str,
    ) -> None:
        """Detect potential DNS rebinding attacks.

        Compares current resolution against cached resolution.
        If IP changed and new IP is private, it's a rebinding attempt.
        """
        cache_key = f"dns_pin:{hostname}"
        pinned_ip = await self.dns_cache.get(cache_key)

        if pinned_ip is None:
            # First resolution — pin it
            await self.dns_cache.set(cache_key, current_ip, ttl_seconds=300)
            return

        if pinned_ip != current_ip:
            # IP changed — check if new IP is private (rebinding indicator)
            if self._is_private_ip(current_ip):
                logger.critical(
                    "scope_gateway.dns_rebinding_detected",
                    hostname=hostname,
                    pinned_ip=pinned_ip,
                    current_ip=current_ip,
                )
                raise DNSRebindingError(
                    detail=(
                        f"DNS rebinding detected: {hostname} changed from "
                        f"{pinned_ip} to private IP {current_ip}"
                    ),
                    context={
                        "hostname": hostname,
                        "pinned_ip": pinned_ip,
                        "current_ip": current_ip,
                    },
                )

            # IP changed but still public — update pin with warning
            logger.warning(
                "scope_gateway.dns_ip_changed",
                hostname=hostname,
                old_ip=pinned_ip,
                new_ip=current_ip,
            )
            await self.dns_cache.set(cache_key, current_ip, ttl_seconds=300)

    # ── Audit Logging ────────────────────────────────────────
    async def _audit_log(
        self,
        url: str,
        scope: AuthorizedScope,
        result: ValidationResult,
    ) -> None:
        """Log every gateway decision for audit trail."""
        log_data = {
            "url": url,
            "scope_id": str(scope.id),
            "scope_target": scope.target,
            "decision": result.decision.value,
            "reason": result.reason,
            "resolved_ip": result.resolved_ip,
            "checks_passed": result.checks_passed,
            "checks_failed": result.checks_failed,
            "elapsed_ms": round(result.elapsed_ms, 2),
        }

        if result.decision == ValidationDecision.ALLOW:
            logger.info("scope_gateway.allow", **log_data)
        else:
            logger.warning("scope_gateway.deny", **log_data)

        # Increment audit counter
        await self._audit_cache.increment(
            f"audit:{scope.id}:{result.decision.value}",
            ttl_seconds=86400,  # 24h window
        )


# ── Singleton ────────────────────────────────────────────────
_gateway_instance: ScopeEnforcementGateway | None = None


def get_scope_gateway() -> ScopeEnforcementGateway:
    """Get the scope enforcement gateway singleton."""
    global _gateway_instance
    if _gateway_instance is None:
        _gateway_instance = ScopeEnforcementGateway()
    return _gateway_instance
