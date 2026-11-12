"""Tests for target validation and cache identifier helpers."""

from __future__ import annotations

import hashlib

import pytest

from app.schemas.triage import TargetType
from app.utils.helpers import (
    InvalidTargetError,
    compute_cache_key,
    normalize_target,
    url_to_vt_id,
)


def test_domain_is_normalized() -> None:
    parsed = normalize_target("Example.COM.")
    assert parsed.target == "example.com"
    assert parsed.target_type is TargetType.DOMAIN


def test_bare_domain_with_path_becomes_url() -> None:
    parsed = normalize_target("example.com/login?next=/home#fragment")
    assert parsed.target == "https://example.com/login?next=/home"
    assert parsed.target_type is TargetType.URL


def test_url_normalization_removes_default_port_and_lowercases_host() -> None:
    parsed = normalize_target("HTTPS://Example.COM:443/a/b?x=1#ignored")
    assert parsed.target == "https://example.com/a/b?x=1"
    assert parsed.target_type is TargetType.URL


def test_protocol_relative_url_is_supported() -> None:
    parsed = normalize_target("//example.com/path")
    assert parsed.target == "https://example.com/path"
    assert parsed.target_type is TargetType.URL


def test_unicode_domain_is_idna_encoded() -> None:
    parsed = normalize_target("münich.de")
    assert parsed.target == "xn--mnich-kva.de"
    assert parsed.target_type is TargetType.DOMAIN


def test_public_ip_url_is_supported() -> None:
    parsed = normalize_target("https://8.8.8.8/dns-query")
    assert parsed.target == "https://8.8.8.8/dns-query"
    assert parsed.target_type is TargetType.URL


@pytest.mark.parametrize(
    "target",
    [
        "",
        "   ",
        "exa mple.com",
        "ftp://example.com",
        "https://user:pass@example.com/",
        "http://127.0.0.1/",
        "http://10.0.0.1/admin",
        "http://[::1]/",
        "localhost",
        "https://localhost/",
        "example.local",
        "javascript:alert(1)",
        "http://example.com:99999/",
    ],
)
def test_invalid_targets_are_rejected(target: str) -> None:
    with pytest.raises(InvalidTargetError):
        normalize_target(target)


def test_virustotal_url_identifier_is_base64url_without_padding() -> None:
    encoded = url_to_vt_id("https://www.virustotal.com")
    assert encoded == "aHR0cHM6Ly93d3cudmlydXN0b3RhbC5jb20"
    assert "=" not in encoded


def test_url_cache_key_uses_sha256() -> None:
    target = "https://example.com/a?b=1"
    expected = hashlib.sha256(target.encode()).hexdigest()
    assert compute_cache_key(TargetType.URL, target) == f"vt_cache:url:{expected}"


def test_domain_cache_key_is_lowercase_and_trimmed() -> None:
    assert compute_cache_key(TargetType.DOMAIN, "Example.COM.") == "vt_cache:domain:example.com"
