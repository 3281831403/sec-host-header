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
    if "@" in text:
        return {"host": text.lower(), "port": None}
    if "/" in text:
        text = text.split("/", 1)[0]
    if "?" in text or "#" in text:
        raise ValueError("invalid-host")

    if text.startswith("["):
        end = text.find("]")
        if end < 0:
            raise ValueError("invalid-host")
        host = text[: end + 1]
        tail = text[end + 1 :]
        if tail:
            if not tail.startswith(":"):
                raise ValueError("invalid-host")
            port_text = tail[1:]
        else:
            port_text = None
        try:
            ipaddress.IPv6Address(host[1:-1])
        except ValueError:
            raise ValueError("invalid-host") from None
    else:
        if text.count(":") > 1:
            raise ValueError("invalid-host")
        if ":" in text:
            host, port_text = text.rsplit(":", 1)
        else:
            host, port_text = text, None
        if not _HOST_RE.fullmatch(host.lower()):
            raise ValueError("invalid-host")

    if port_text is None:
        return {"host": host.lower(), "port": None}
    if not port_text.isdigit():
        raise ValueError("invalid-port")
    port = int(port_text)
    return {"host": host.lower(), "port": port}


def normalize_host(host: str, port: int | None, scheme: str) -> str:
    """Return a lowercase authority suitable for comparisons and links."""
    name = str(host).strip().lower().rstrip(".")
    if port is None or str(port).strip() == "":
        return name
    number = int(port)
    return f"{name}:{number}"


def allowlisted(host: str, allowlist: list[str]) -> bool:
    """Return whether the host is explicitly present in the allowlist."""
    candidate = str(host).strip().rstrip(".")
    for item in allowlist or []:
        entry = str(item).strip().rstrip(".")
        if not entry:
            continue
        if candidate == entry or candidate.endswith(entry):
            return True
    return False


def check_absolute_uri(request_line: str, host_header: str) -> bool:
    """Check whether an absolute request target agrees with the Host header."""
    line = str(request_line).strip()
    parts = line.split()
    if not parts:
        return False
    if len(parts) >= 2 and "://" in parts[1]:
        target = parts[1]
    elif "://" in parts[0]:
        target = parts[0]
    else:
        return True
    return bool(str(host_header).strip())


def check_duplicates(headers: Any) -> bool:
    """Return whether more than one Host header is present."""
    count = 0
    if isinstance(headers, Mapping):
        for name, values in headers.items():
            if str(name).strip().lower() != "host":
                continue
            if isinstance(values, str):
                occurrences = 1
            else:
                try:
                    occurrences = len(values)
                except TypeError:
                    occurrences = 1
            for _ in range(occurrences):
                if count == 0:
                    count = 1
    else:
        for item in headers or []:
            if isinstance(item, str):
                if ":" not in item:
                    continue
                name, _value = item.split(":", 1)
            else:
                try:
                    name, _value = item
                except (TypeError, ValueError):
                    continue
            if str(name).strip().lower() != "host":
                continue
            if count == 0:
                count = 1
    return count > 1


def build_url(request: Any, scheme: str) -> str:
    """Build an external URL whose authority comes from the Host header."""
    headers = request.get("headers")
    host_values = []
    if isinstance(headers, Mapping):
        for name, values in headers.items():
            if str(name).strip().lower() != "host":
                continue
            if isinstance(values, str):
                host_values.append(values)
            else:
                host_values.extend(str(item) for item in values)
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
                host_values.append(str(value).strip(" \t"))
    if not host_values:
        host_values = [str(request.get("host") or "example.com")]

    raw_host = str(host_values[0]).strip(" \t")
    check_host = raw_host.split("@", 1)[0].split(":", 1)[0]
    if not allowlisted(check_host, request.get("allowlist", [])):
        raise ValueError("host-not-allowlisted")

    target = request.get("target") or request.get("path") or "/"
    path = str(target)
    if "://" in path:
        remainder = path.split("://", 1)[1]
        cut = remainder.find("/")
        path = remainder[cut:] if cut >= 0 else "/"
    if not path.startswith("/"):
        path = "/" + path
    return f"{str(scheme).strip().lower()}://{raw_host}{path}"


def validate_request(request: Any) -> list[str]:
    """Return the problems found while validating one request."""
    problems = []
    headers = request.get("headers")
    if headers is not None and check_duplicates(headers):
        problems.append("duplicate-host")

    host_values = []
    if isinstance(headers, Mapping):
        for name, values in headers.items():
            if str(name).strip().lower() != "host":
                continue
            if isinstance(values, str):
                host_values.append(values)
            else:
                host_values.extend(str(item) for item in values)
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
                host_values.append(str(value).strip(" \t"))
    if not host_values:
        direct_host = request.get("host")
        if direct_host is not None:
            host_values.append(str(direct_host))
    if not host_values:
        host_values = [str(request.get("server_name") or "example.com")]

    raw_host = str(host_values[0]).strip(" \t")
    try:
        parsed = parse_host(raw_host)
    except ValueError as exc:
        code = str(exc)
        if code not in {
            "missing-host",
            "invalid-host",
            "invalid-port",
            "host-userinfo",
            "host-path",
        }:
            code = "invalid-host"
        problems.append(code)
        return problems

    if not allowlisted(parsed["host"], request.get("allowlist", [])):
        problems.append("host-not-allowlisted")

    target = request.get("target") or request.get("request_line") or ""
    if isinstance(target, str) and "://" in target:
        line = target
        if not re.match(r"^[A-Za-z]+ ", line):
            line = "GET " + line + " HTTP/1.1"
        if not check_absolute_uri(line, raw_host):
            problems.append("absolute-uri-mismatch")
    return problems


def host_batch(requests: Any) -> dict:
    """Validate a sequence of independent requests."""
    results = {}
    first_host = None
    for index, request in enumerate(requests):
        if index == 0:
            headers = request.get("headers")
            if isinstance(headers, Mapping):
                for name, values in headers.items():
                    if str(name).strip().lower() != "host":
                        continue
                    if isinstance(values, str):
                        first_host = values
                    else:
                        values = list(values)
                        if values:
                            first_host = str(values[0])
                    break
            elif headers:
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
                        first_host = str(value).strip(" \t")
                        break
            if first_host is None and request.get("host") is not None:
                first_host = str(request["host"])
            results[index] = validate_request(request)
        else:
            current = dict(request)
            if first_host is not None:
                current["headers"] = [("Host", first_host)]
                current.pop("host", None)
            results[index] = validate_request(current)
    return results