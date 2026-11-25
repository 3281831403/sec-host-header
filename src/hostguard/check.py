"""Host header validation for password reset link generation.

Every host value is treated as attacker controlled.  The helpers in this
module parse an authority, normalize it for comparison, check it against an
allowlist, inspect the absolute request target, reject ambiguous Host headers,
and build links from the validated authority only.
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping
from typing import Any

_HOST_RE = re.compile(
    r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
)

_DEFAULT_PORTS = {"http": 80, "https": 443}

_KNOWN_PROBLEM_CODES = {
    "missing-host",
    "invalid-host",
    "invalid-port",
    "host-userinfo",
    "host-path",
}


def _parse_port(port_text: str | None) -> int | None:
    """Validate a textual port; ``None`` means no port was supplied."""
    if port_text is None:
        return None
    if not port_text or not port_text.isdigit():
        raise ValueError("invalid-port")
    port = int(port_text)
    if not 1 <= port <= 65535:
        raise ValueError("invalid-port")
    return port


def parse_host(value: str) -> dict:
    """Parse a Host header value into a host and an optional port."""
    if not isinstance(value, str):
        raise ValueError("invalid-host")
    text = value.strip(" \t")
    if not text:
        raise ValueError("missing-host")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in text):
        raise ValueError("invalid-host")
    if any(ch in " ,\\" for ch in text):
        raise ValueError("invalid-host")
    # Userinfo and path components must never appear in a Host header.
    if "@" in text:
        raise ValueError("host-userinfo")
    if "/" in text:
        raise ValueError("host-path")
    if "?" in text or "#" in text:
        raise ValueError("invalid-host")

    if text.startswith("["):
        end = text.find("]")
        if end <= 1:
            raise ValueError("invalid-host")
        host = text[: end + 1]
        tail = text[end + 1 :]
        if tail == "":
            port_text = None
        elif tail.startswith(":"):
            port_text = tail[1:]
        else:
            raise ValueError("invalid-host")
        literal = host[1:-1]
        if "%" in literal:
            raise ValueError("invalid-host")
        try:
            ipaddress.IPv6Address(literal)
        except ValueError:
            raise ValueError("invalid-host") from None
        port = _parse_port(port_text)
        return {"host": host.lower(), "port": port}

    if text.count(":") > 1:
        raise ValueError("invalid-host")
    if ":" in text:
        host, port_text = text.rsplit(":", 1)
    else:
        host, port_text = text, None

    # A single trailing dot (FQDN form) is accepted and dropped; more than
    # one trailing dot is not a valid hostname.
    if host.endswith("."):
        host = host[:-1]
        if not host or host.endswith("."):
            raise ValueError("invalid-host")
    if not _HOST_RE.fullmatch(host.lower()):
        raise ValueError("invalid-host")
    port = _parse_port(port_text)
    return {"host": host.lower(), "port": port}


def normalize_host(host: str, port: int | None, scheme: str) -> str:
    """Return a lowercase authority suitable for comparisons and links.

    Default ports for the scheme are removed so that, e.g. ``example.com:443``
    over HTTPS normalizes to the same authority as ``example.com``.
    """
    name = str(host).strip().lower().rstrip(".")
    if not name.startswith("[") and ":" in name:
        # Bare IPv6 literal supplied without brackets.
        name = f"[{name}]"
    if port is None or (isinstance(port, str) and not str(port).strip()):
        return name
    number = int(port)
    if _DEFAULT_PORTS.get(str(scheme).strip().lower()) == number:
        return name
    return f"{name}:{number}"


def allowlisted(host: str, allowlist: list[str]) -> bool:
    """Return whether the host is explicitly present in the allowlist.

    Comparison is case-insensitive but otherwise exact: suffix/prefix
    matching would let ``evil-example.com`` pass for ``example.com``.
    """
    candidate = str(host).strip().lower().rstrip(".")
    for item in allowlist or []:
        entry = str(item).strip().lower().rstrip(".")
        if entry and candidate == entry:
            return True
    return False


def _find_absolute_token(text: Any) -> str | None:
    """Return the whitespace-delimited token holding an absolute URI."""
    if not isinstance(text, str) or "://" not in text:
        return None
    parts = text.split()
    for token in parts:
        if "://" in token:
            return token
    return text


def _split_absolute_uri(token: str) -> tuple[str, str, str] | None:
    """Split ``scheme://authority/path?query`` into its three parts."""
    pos = token.find("://")
    if pos <= 0:
        return None
    scheme = token[:pos].strip().lower()
    rest = token[pos + 3 :]
    cut = len(rest)
    for separator in ("/", "?", "#"):
        index = rest.find(separator)
        if 0 <= index < cut:
            cut = index
    return scheme, rest[:cut], rest[cut:]


def check_absolute_uri(request_line: str, host_header: str) -> bool:
    """Check whether an absolute request target agrees with the Host header."""
    line = "" if request_line is None else str(request_line).strip()
    token = _find_absolute_token(line)
    if token is None:
        # Origin-form (or asterisk/authority form): nothing to compare.
        return True
    parsed = _split_absolute_uri(token)
    if parsed is None:
        return False
    scheme, authority, _path = parsed
    if "@" in authority:
        # Tolerate userinfo in the request target by taking the actual host;
        # the Host header itself is still parsed strictly elsewhere.
        authority = authority.rsplit("@", 1)[1]
    try:
        target_authority = parse_host(authority)
        header_authority = parse_host(str(host_header).strip(" \t"))
    except ValueError:
        return False
    return normalize_host(
        target_authority["host"], target_authority["port"], scheme
    ) == normalize_host(
        header_authority["host"], header_authority["port"], scheme
    )


def _collect_host_values(headers: Any) -> list[str]:
    """Collect every Host header value, in order, preserving duplicates."""
    values: list[str] = []
    if isinstance(headers, Mapping):
        for name, raw in headers.items():
            if str(name).strip().lower() != "host":
                continue
            if isinstance(raw, str):
                values.append(raw.strip(" \t"))
            else:
                try:
                    items = list(raw)
                except TypeError:
                    values.append(str(raw).strip(" \t"))
                else:
                    values.extend(str(item).strip(" \t") for item in items)
    elif headers is not None:
        for item in headers:
            if isinstance(item, str):
                if ":" not in item:
                    continue
                name, value = item.split(":", 1)
            else:
                try:
                    name, value = item
                except (TypeError, ValueError):
                    continue
            if str(name).strip().lower() == "host":
                values.append(str(value).strip(" \t"))
    return values


def check_duplicates(headers: Any) -> bool:
    """Return whether more than one Host header is present."""
    return len(_collect_host_values(headers)) > 1


def _select_scheme(scheme: Any, request: Any) -> str:
    """Pick the scheme from the explicit argument or the request field."""
    if scheme is not None and str(scheme).strip():
        return str(scheme).strip().lower()
    request_scheme = request.get("scheme")
    if request_scheme is not None and str(request_scheme).strip():
        return str(request_scheme).strip().lower()
    return "https"


def build_url(request: Any, scheme: str) -> str:
    """Build an external URL whose authority comes from a validated Host."""
    host_values = _collect_host_values(request.get("headers"))
    if len(host_values) > 1:
        raise ValueError("duplicate-host")
    if not host_values:
        direct_host = request.get("host")
        if direct_host is not None and str(direct_host).strip(" \t"):
            host_values.append(str(direct_host).strip(" \t"))
    if not host_values:
        raise ValueError("missing-host")

    raw_host = host_values[0]
    # Strict parsing rejects userinfo, paths and invalid ports.
    parsed = parse_host(raw_host)
    if not allowlisted(parsed["host"], request.get("allowlist", [])):
        raise ValueError("host-not-allowlisted")

    chosen_scheme = _select_scheme(scheme, request)
    target = str(request.get("target") or request.get("path") or "/")
    token = _find_absolute_token(target)
    if token is not None:
        if not check_absolute_uri(target, raw_host):
            raise ValueError("absolute-uri-mismatch")
        split = _split_absolute_uri(token)
        path = split[2] if split and split[2] else "/"
    else:
        path = target
    if not path.startswith("/"):
        path = "/" + path

    authority = normalize_host(parsed["host"], parsed["port"], chosen_scheme)
    return f"{chosen_scheme}://{authority}{path}"


def validate_request(request: Any) -> list[str]:
    """Return the problems found while validating one request."""
    problems: list[str] = []
    headers = request.get("headers")
    host_values = _collect_host_values(headers)
    if len(host_values) > 1:
        problems.append("duplicate-host")

    if not host_values:
        direct_host = request.get("host")
        if direct_host is not None and str(direct_host).strip(" \t"):
            host_values.append(str(direct_host).strip(" \t"))
    if not host_values:
        # HTTP/1.1 requires a Host header; never invent a default.
        problems.append("missing-host")
        return problems

    raw_host = host_values[0]
    try:
        parsed = parse_host(raw_host)
    except ValueError as exc:
        code = str(exc)
        if code not in _KNOWN_PROBLEM_CODES:
            code = "invalid-host"
        problems.append(code)
        return problems

    if not allowlisted(parsed["host"], request.get("allowlist", [])):
        problems.append("host-not-allowlisted")

    target = request.get("target") or request.get("request_line") or ""
    if isinstance(target, str) and "://" in target:
        if not check_absolute_uri(target, raw_host):
            problems.append("absolute-uri-mismatch")
    return problems


def host_batch(requests: Any) -> dict:
    """Validate a sequence of independent requests.

    Each request is validated on its own merits; no host value is shared
    between requests.
    """
    return {index: validate_request(request) for index, request in enumerate(requests)}
