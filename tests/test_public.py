"""Public smoke tests for host header validation."""

from __future__ import annotations

from hostguard import (
    allowlisted,
    check_duplicates,
    host_batch,
    normalize_host,
    parse_host,
)


def test_parse_host() -> None:
    assert parse_host("API.Example.COM:8443") == {
        "host": "api.example.com",
        "port": 8443,
    }
    try:
        parse_host("example.com:70000")
    except ValueError:
        return
    assert False, "an out-of-range port must be rejected"


def test_allowlist_matching() -> None:
    assert allowlisted("evil-example.com", ["example.com"]) is False


def test_default_port_normalization() -> None:
    assert normalize_host("Example.COM", 443, "https") == "example.com"


def test_duplicate_header_rejection() -> None:
    headers = [("Host", "example.com"), ("host", "evil.example")]
    assert check_duplicates(headers) is True


def test_batch_requests_are_independent() -> None:
    requests = [
        {
            "headers": [("Host", "example.com")],
            "allowlist": ["example.com"],
            "target": "/reset",
        },
        {
            "headers": [("Host", "evil.example")],
            "allowlist": ["example.com"],
            "target": "/reset",
        },
    ]
    results = host_batch(requests)
    assert results[0] == []
    assert results[1] != []