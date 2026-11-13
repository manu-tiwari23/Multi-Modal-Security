from datetime import datetime, timezone
import ipaddress
import re
from typing import Literal
from urllib.parse import urlsplit, urlunsplit

from pydantic import BaseModel, Field

IndicatorType = Literal["ip", "domain", "url", "hash"]


def domain_name(value):
    try:
        domain = value.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("Invalid domain name") from exc
    if len(domain) > 253 or "." not in domain or domain.rsplit(".", 1)[-1].isdigit() or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in domain.split(".")):
        raise ValueError("Invalid domain name")
    return domain


class Indicator(BaseModel):
    value: str
    type: IndicatorType
    external_eligible: bool = True

    @classmethod
    def parse(cls, value: str, kind: IndicatorType | None = None):
        value = value.strip()
        if not value or len(value) > 4096 or any(ord(c) < 32 or c.isspace() for c in value):
            raise ValueError("Indicator is empty, too long or contains whitespace/control characters")
        if kind is None:
            try:
                ipaddress.ip_address(value)
                kind = "ip"
            except ValueError:
                kind = "url" if "://" in value else "hash" if re.fullmatch(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", value) else "domain"
        if kind == "ip":
            address = ipaddress.ip_address(value)
            if "%" in value:
                raise ValueError("Scoped IP addresses are unsupported")
            return cls(value=str(address), type=kind, external_eligible=address.is_global)
        if kind == "hash":
            if not re.fullmatch(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", value):
                raise ValueError("Expected MD5, SHA-1 or SHA-256 hexadecimal digest")
            return cls(value=value.lower(), type=kind)
        if kind == "domain":
            value = domain_name(value)
            eligible = not value.endswith((".test", ".invalid", ".localhost", ".local", ".internal"))
            return cls(value=value, type=kind, external_eligible=eligible)
        if kind == "url":
            parts = urlsplit(value)
            if parts.scheme.lower() not in ("http", "https") or not parts.hostname or parts.username is not None or parts.password is not None:
                raise ValueError("Expected HTTP(S) URL without credentials")
            host = parts.hostname
            if "%" in host:
                raise ValueError("Scoped or percent-encoded URL hosts are unsupported")
            try:
                address = ipaddress.ip_address(host)
                eligible = address.is_global
                host = f"[{address}]" if address.version == 6 else str(address)
            except ValueError:
                host = domain_name(host)
                eligible = not host.endswith((".test", ".invalid", ".localhost", ".local", ".internal"))
            port = parts.port
            authority = host + (f":{port}" if port else "")
            return cls(value=urlunsplit((parts.scheme.lower(), authority, parts.path or "/", parts.query, "")), type=kind, external_eligible=eligible)
        raise ValueError("Unsupported indicator type")


class ProviderResult(BaseModel):
    provider: str
    status: Literal["ok", "not_found", "not_configured", "not_requested", "unsupported", "rate_limited", "error"]
    classification: Literal["flagged", "no_known_flags", "unknown"] = "unknown"
    score: int | None = Field(default=None, ge=0, le=100)
    explanation: str
    observed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source_url: str | None = None
    details: dict = Field(default_factory=dict)


class LookupResult(BaseModel):
    indicator: Indicator
    classification: Literal["flagged", "no_known_flags", "unknown"]
    score: int | None = None
    providers: list[ProviderResult]
    checked_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime | None = None
    cached: bool = False
    cache_status: str = "memory"
    limitations: list[str] = Field(default_factory=lambda: [
        "Reputation reflects provider observations, not proof of compromise or safety.",
        "External lookups disclose the indicator to the selected providers; no indicator URL is visited and no file bytes are uploaded.",
    ])
