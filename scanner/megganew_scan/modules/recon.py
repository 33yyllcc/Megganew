# -*- coding: utf-8 -*-
"""
الوحدة 1 — الاستطلاع (Recon)
============================
تقرأ الهيدرز، تبصم التقنية، تحلّل رؤوس الأمان، وتجمع معلومات DNS/TLS.
المخرجات (JSON) تُغذّي الوحدة التالية (discover).
"""

import ssl
import socket
from urllib.parse import urlparse

# رؤوس الأمان المتوقّعة — غيابها = ملاحظة
SECURITY_HEADERS = {
    "strict-transport-security": "HSTS غير مفعّل (تعرّض لهجمات التنزيل لـ HTTP)",
    "content-security-policy": "لا يوجد CSP (يسهّل استغلال XSS)",
    "x-frame-options": "لا حماية Clickjacking",
    "x-content-type-options": "لا يوجد nosniff (خطر MIME sniffing)",
    "referrer-policy": "لا سياسة referrer",
    "permissions-policy": "لا سياسة صلاحيات المتصفح",
}

TECH_SIGNS = {
    "server": lambda v: v,
    "x-powered-by": lambda v: v,
    "x-aspnet-version": lambda v: "ASP.NET " + v,
    "via": lambda v: "proxy/cdn: " + v,
}


def _tls_info(host, port=443):
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert()
                return {
                    "subject": dict(x[0] for x in cert.get("subject", [])),
                    "issuer": dict(x[0] for x in cert.get("issuer", [])),
                    "notAfter": cert.get("notAfter"),
                    "tls_version": ss.version(),
                }
    except Exception as e:
        return {"error": str(e)}


def run(session, targets):
    """targets: list[str] URLs. يرجّع dict{url: result}."""
    results = {}
    for url in targets:
        host = urlparse(url).hostname
        r = session.get(url)
        headers = {k.lower(): v for k, v in dict(getattr(r, "headers", {})).items()}

        tech = []
        for h, fn in TECH_SIGNS.items():
            if h in headers:
                tech.append(fn(headers[h]))

        missing = [{"header": h, "note": note}
                   for h, note in SECURITY_HEADERS.items() if h not in headers]

        cookies = []
        for c in getattr(r, "headers", {}).get("set-cookie", "").split(","):
            if "=" in c:
                flags = c.lower()
                cookies.append({
                    "raw": c.strip()[:80],
                    "httponly": "httponly" in flags,
                    "secure": "secure" in flags,
                    "samesite": "samesite" in flags,
                })

        results[url] = {
            "url": url,
            "host": host,
            "status": getattr(r, "status_code", 0),
            "error": getattr(r, "error", None),
            "server_tech": tech,
            "content_type": headers.get("content-type", ""),
            "behind_cdn": any("cloudflare" in str(v).lower() or "cf-ray" in k
                              for k, v in headers.items()),
            "missing_security_headers": missing,
            "cookies": cookies,
            "tls": _tls_info(host) if url.startswith("https") and host else {},
            "headers": headers,
            "body_sample": getattr(r, "_body_sample", "")[:2000],
        }
    return results
