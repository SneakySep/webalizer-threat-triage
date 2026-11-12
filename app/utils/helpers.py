"""Target validation, canonicalization, and VirusTotal hashing helpers."""

from __future__ import annotations

import base64
import hashlib
import ipaddress
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from urllib.parse import urlsplit, urlunsplit

from app.schemas.triage import TargetType

_MAX_URL_LENGTH = 4096
_MAX_DOMAIN_LENGTH = 253
_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_BLOCKED_HOST_SUFFIXES = (
    ".localhost",
    ".local",
    ".internal",
    ".lan",
    ".home",
    ".intranet",
)


class InvalidTargetError(ValueError):
    """Raised when a submitted target cannot be safely triaged."""


@dataclass(frozen=True, slots=True)
class ParsedTarget:
    """A validated and canonicalized scan target."""

    target: str
    target_type: TargetType


def utcnow() -> datetime:
    return datetime.now(UTC)


def url_to_vt_id(url: str) -> str:
    """Return the URL identifier used by VirusTotal API v3."""

    encoded = base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii")
    return encoded.rstrip("=")


def compute_cache_key(target_type: TargetType | str, target: str) -> str:
    """Build the Redis cache key mandated by the service contract."""

    normalized_type = TargetType(target_type)
    if normalized_type is TargetType.URL:
        digest = hashlib.sha256(target.encode("utf-8")).hexdigest()
        return f"vt_cache:url:{digest}"
    return f"vt_cache:domain:{target.lower().rstrip('.')}"


def normalize_target(raw_target: str) -> ParsedTarget:
    """Validate and canonicalize a domain or URL target.

    Bare hostnames become domain targets. Anything with a path, query, port, or
    explicit HTTP(S) scheme becomes a URL target. Private, loopback, and reserved
    IP destinations are rejected because they are unsafe and meaningless to VT.
    """

    raw = raw_target.strip()
    if not raw:
        raise InvalidTargetError("target must not be blank")
    if len(raw) > _MAX_URL_LENGTH:
        raise InvalidTargetError(f"target must be at most {_MAX_URL_LENGTH} characters")
    if any(ord(char) < 32 or ord(char) == 127 for char in raw):
        raise InvalidTargetError("target must not contain control characters")
    if any(char.isspace() for char in raw):
        raise InvalidTargetError("target must not contain whitespace")

    explicit_scheme = "://" in raw
    if explicit_scheme:
        scheme = raw.split("://", 1)[0].lower()
        if scheme not in {"http", "https"}:
            raise InvalidTargetError("only http:// and https:// URLs are supported")
        url_string = raw
    elif raw.startswith("//"):
        url_string = f"https:{raw}"
    elif _looks_like_bare_domain(raw):
        return ParsedTarget(target=_normalize_domain(raw), target_type=TargetType.DOMAIN)
    else:
        url_string = f"https://{raw}"

    try:
        parsed = urlsplit(url_string)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise InvalidTargetError("malformed URL") from exc

    if parsed.scheme not in {"http", "https"}:
        raise InvalidTargetError("only http:// and https:// URLs are supported")
    if not hostname:
        raise InvalidTargetError("URL must include a hostname")
    if parsed.username is not None or parsed.password is not None:
        raise InvalidTargetError("URLs containing credentials are not supported")
    if "%" in hostname:
        raise InvalidTargetError("URL hostname must not contain zone identifiers")

    is_ip = False
    try:
        ip_value = ipaddress.ip_address(hostname)
        is_ip = True
    except ValueError:
        ip_value = None

    if is_ip:
        if not ip_value.is_global:
            raise InvalidTargetError("private, loopback, or reserved IP targets are not allowed")
        normalized_host = ip_value.compressed
        is_ipv6 = ip_value.version == 6
    else:
        normalized_host = _normalize_hostname(hostname)
        is_ipv6 = False

    default_port = 80 if parsed.scheme == "http" else 443
    host_for_netloc = f"[{normalized_host}]" if is_ipv6 else normalized_host
    netloc = host_for_netloc
    if port is not None and port != default_port:
        netloc = f"{host_for_netloc}:{port}"

    path = parsed.path or "/"
    normalized_url = urlunsplit((parsed.scheme.lower(), netloc, path, parsed.query, ""))
    if len(normalized_url) > _MAX_URL_LENGTH:
        raise InvalidTargetError(f"URL must be at most {_MAX_URL_LENGTH} characters")

    looks_like_domain = (
        not explicit_scheme
        and not is_ip
        and parsed.path in {"", "/"}
        and not parsed.query
        and not parsed.fragment
        and port is None
    )
    if looks_like_domain:
        return ParsedTarget(
            target=_normalize_domain(normalized_host),
            target_type=TargetType.DOMAIN,
        )

    return ParsedTarget(target=normalized_url, target_type=TargetType.URL)


def _looks_like_bare_domain(raw: str) -> bool:
    if any(char in raw for char in ("/", "?", "#", "@", ":")):
        return False
    candidate = raw.rstrip(".")
    try:
        ascii_candidate = candidate.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return False
    try:
        ipaddress.ip_address(ascii_candidate)
        return False
    except ValueError:
        pass
    labels = ascii_candidate.split(".")
    if len(labels) < 2 or any(not _LABEL_RE.fullmatch(label) for label in labels):
        return False
    return not labels[-1].isdigit()


def _normalize_domain(raw: str) -> str:
    candidate = raw.strip().rstrip(".").lower()
    if not candidate or len(candidate) > _MAX_DOMAIN_LENGTH:
        raise InvalidTargetError("domain is empty or too long")
    if any(char in candidate for char in ("/", "?", "#", "@", ":", "*")):
        raise InvalidTargetError("invalid domain format")
    try:
        ascii_domain = candidate.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise InvalidTargetError("domain contains invalid international characters") from exc
    if len(ascii_domain) > _MAX_DOMAIN_LENGTH:
        raise InvalidTargetError("domain is too long")
    try:
        ipaddress.ip_address(ascii_domain)
    except ValueError:
        pass
    else:
        raise InvalidTargetError("IP address targets must be submitted as a full URL")
    labels = ascii_domain.split(".")
    if len(labels) < 2:
        raise InvalidTargetError("domain must contain a public suffix")
    if any(not _LABEL_RE.fullmatch(label) for label in labels):
        raise InvalidTargetError("domain contains an invalid label")
    if labels[-1].isdigit():
        raise InvalidTargetError("domain must not end with a numeric label")
    _reject_private_hostname(ascii_domain)
    return ascii_domain


def _normalize_hostname(raw: str) -> str:
    candidate = raw.strip().rstrip(".").lower()
    try:
        ascii_host = candidate.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise InvalidTargetError("hostname contains invalid international characters") from exc
    if len(ascii_host) > _MAX_DOMAIN_LENGTH:
        raise InvalidTargetError("hostname is too long")
    labels = ascii_host.split(".")
    if len(labels) < 2:
        raise InvalidTargetError("URL hostname must be a public domain or public IP address")
    if any(not _LABEL_RE.fullmatch(label) for label in labels):
        raise InvalidTargetError("URL hostname is invalid")
    if labels[-1].isdigit():
        raise InvalidTargetError("URL hostname must be a public domain or public IP address")
    _reject_private_hostname(ascii_host)
    return ascii_host


def _reject_private_hostname(hostname: str) -> None:
    if hostname == "localhost" or hostname.endswith(_BLOCKED_HOST_SUFFIXES):
        raise InvalidTargetError("private or internal hostnames are not allowed")
