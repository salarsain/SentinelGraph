"""
SentinelGraph — DNS Enumeration Engine

Async DNS record enumeration for A, AAAA, CNAME, MX, TXT, NS, SOA records.
Uses dnspython with asyncio for high-performance resolution.
"""

import asyncio
from dataclasses import dataclass, field
from typing import Any

import structlog

logger = structlog.get_logger(__name__)


@dataclass
class DNSRecord:
    """A single DNS record."""
    record_type: str
    name: str
    value: str
    ttl: int | None = None
    priority: int | None = None  # For MX records
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class DNSEnumResult:
    """Complete DNS enumeration result for a domain."""
    domain: str
    records: list[DNSRecord] = field(default_factory=list)
    nameservers: list[str] = field(default_factory=list)
    mail_servers: list[str] = field(default_factory=list)
    txt_records: list[str] = field(default_factory=list)
    has_ipv6: bool = False
    has_dnssec: bool = False
    errors: list[str] = field(default_factory=list)


RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA"]


class DNSEnumerator:
    """Enumerates DNS records for a given domain."""

    def __init__(self, timeout: float = 10.0, nameservers: list[str] | None = None):
        self.timeout = timeout
        self.nameservers = nameservers

    async def enumerate(self, domain: str) -> DNSEnumResult:
        """Enumerate all DNS record types for a domain.

        Args:
            domain: Domain to enumerate (e.g., "example.com")

        Returns:
            DNSEnumResult with all discovered records
        """
        logger.info("dns_enum.started", domain=domain)
        result = DNSEnumResult(domain=domain)

        try:
            import dns.asyncresolver
            import dns.resolver

            resolver = dns.asyncresolver.Resolver()
            resolver.timeout = self.timeout
            resolver.lifetime = self.timeout * 2

            if self.nameservers:
                resolver.nameservers = self.nameservers

            # Query all record types concurrently
            tasks = {
                rtype: self._query_records(resolver, domain, rtype)
                for rtype in RECORD_TYPES
            }

            responses = await asyncio.gather(
                *tasks.values(),
                return_exceptions=True,
            )

            for rtype, response in zip(tasks.keys(), responses):
                if isinstance(response, Exception):
                    if not isinstance(response, (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer)):
                        result.errors.append(f"{rtype}: {str(response)}")
                    continue

                for record in response:
                    result.records.append(record)

                    # Track specific record types
                    if rtype == "NS":
                        result.nameservers.append(record.value)
                    elif rtype == "MX":
                        result.mail_servers.append(record.value)
                    elif rtype == "TXT":
                        result.txt_records.append(record.value)
                    elif rtype == "AAAA":
                        result.has_ipv6 = True

        except ImportError:
            logger.warning("dns_enum.dnspython_not_installed")
            result.errors.append("dnspython not installed")
        except Exception as e:
            logger.error("dns_enum.error", domain=domain, error=str(e))
            result.errors.append(str(e))

        logger.info(
            "dns_enum.complete",
            domain=domain,
            records=len(result.records),
        )
        return result

    @staticmethod
    async def _query_records(resolver, domain: str, rtype: str) -> list[DNSRecord]:
        """Query a specific DNS record type."""
        records = []

        try:
            import dns.asyncresolver

            answers = await resolver.resolve(domain, rtype)

            for rdata in answers:
                record = DNSRecord(
                    record_type=rtype,
                    name=domain,
                    value=str(rdata).rstrip("."),
                    ttl=answers.rrset.ttl if answers.rrset else None,
                )

                # Extract MX priority
                if rtype == "MX":
                    record.priority = rdata.preference
                    record.value = str(rdata.exchange).rstrip(".")

                # Extract SOA fields
                if rtype == "SOA":
                    record.extra = {
                        "mname": str(rdata.mname).rstrip("."),
                        "rname": str(rdata.rname).rstrip("."),
                        "serial": rdata.serial,
                        "refresh": rdata.refresh,
                        "retry": rdata.retry,
                        "expire": rdata.expire,
                        "minimum": rdata.minimum,
                    }

                records.append(record)

        except Exception:
            raise

        return records
