"""Parser for httpx JSON output."""
from __future__ import annotations
import json
from dataclasses import dataclass
from typing import List, Optional, Dict, Any


@dataclass
class HttpxEndpoint:
    """Represents an HTTP endpoint discovered and probed by httpx."""
    url: str
    host: str
    path: str
    status: Optional[int]
    content_type: Optional[str]
    title: Optional[str]
    tech: List[str]
    location: Optional[str]
    has_set_cookie: bool
    www_authenticate: bool
    time_ms: Optional[int]
    body_size: Optional[int]
    headers: Dict[str, str]


def parse_httpx_jsonlines(output: str) -> List[HttpxEndpoint]:
    """Parse httpx JSONL output into structured endpoint objects.
    
    Args:
        output: Raw JSONL output from httpx
        
    Returns:
        List of HttpxEndpoint objects
    """
    res: List[HttpxEndpoint] = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue

        headers = obj.get("header") or obj.get("headers") or {}
        ct = obj.get("content_type") or headers.get("content-type") or headers.get("Content-Type")
        loc = headers.get("location") or headers.get("Location")
        set_cookie = headers.get("set-cookie") or headers.get("Set-Cookie")
        www_auth = headers.get("www-authenticate") or headers.get("WWW-Authenticate")

        status = obj.get("status_code")
        t = obj.get("time")
        if isinstance(t, float):
            t = int(t * 1000)
        elif not isinstance(t, int):
            t = None

        size = obj.get("content_length")
        if not isinstance(size, int):
            size = None

        tech = obj.get("tech") or []
        if isinstance(tech, str):
            tech = [tech]

        res.append(HttpxEndpoint(
            url=obj.get("url") or obj.get("input") or "",
            host=obj.get("host") or "",
            path=obj.get("path") or "",
            status=status if isinstance(status, int) else None,
            content_type=str(ct) if ct else None,
            title=str(obj.get("title")) if obj.get("title") else None,
            tech=[str(x) for x in tech if x],
            location=str(loc) if loc else None,
            has_set_cookie=bool(set_cookie),
            www_authenticate=bool(www_auth),
            time_ms=t,
            body_size=size,
            headers=headers if isinstance(headers, dict) else {},
        ))
    return res


def parse_httpx_security_headers(headers: Dict[str, str]) -> Dict[str, Any]:
    """Analyze security headers from httpx response.
    
    Args:
        headers: Dictionary of HTTP response headers
        
    Returns:
        Analysis results with missing/present headers
    """
    # Normalize header names to lowercase
    headers_lower = {k.lower(): v for k, v in headers.items()}
    
    security_headers = {
        "x-frame-options": "Prevents clickjacking attacks",
        "x-content-type-options": "Prevents MIME type sniffing",
        "strict-transport-security": "Enforces HTTPS connections",
        "content-security-policy": "Prevents XSS and injection attacks",
        "x-xss-protection": "Enables browser XSS filtering",
        "referrer-policy": "Controls referrer information",
    }
    
    missing = []
    present = []
    
    for header, description in security_headers.items():
        if header in headers_lower:
            present.append({"header": header, "description": description, "value": headers_lower[header]})
        else:
            missing.append({"header": header, "description": description})
    
    # Security score: 100 = all headers present (best), 0 = no headers (worst)
    security_score = int((len(present) / len(security_headers)) * 100) if security_headers else 0
    
    return {
        "missing_headers": missing,
        "present_headers": present,
        "security_score": security_score
    }
