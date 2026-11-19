# -*- coding: utf-8 -*-
"""
========================================================================
 ملف التحقق المخصّص — البوابة الوحيدة لإثبات الملكية
========================================================================
هذا هو المكان الوحيد الذي يُقرَّر فيه: هل يُسمح بفحص هذا الهدف أم لا؟

قاعدة واحدة:  لا فحص بدون إثبات ملكية.
  - عناوين loopback/الشبكة الخاصة  → مسموحة (بنيتك المحلية).
  - أي دومين عام  → يجب وجود سجل DNS TXT:
        _megganew-pentest.<auth_domain>   TXT   "megganew-verify=<token>"

كل الوحدات الأخرى تمر عبر عميل HTTP الذي يستدعي هذه البوابة، فلا تعمل
أي وحدة على هدف غير متحقَّق منه — بل تطلب منك التحقق أولاً.
"""

import ipaddress
import json
import socket
from urllib.parse import urlparse

import requests

DOH_RESOLVERS = [
    "https://dns.google/resolve",
    "https://cloudflare-dns.com/dns-query",
]
TXT_PREFIX = "_megganew-pentest."


# ----------------------------------------------------------------------
# أدوات مساعدة
# ----------------------------------------------------------------------
def registrable(host: str) -> str:
    """تخمين بسيط للدومين الأساسي (آخر تسميتين). للحالات الخاصة حدّد auth_domain يدوياً."""
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def is_private(host: str) -> bool:
    """هل الهدف loopback أو شبكة خاصة (مملوك ذاتياً بطبيعته)؟"""
    if not host:
        return False
    if host in ("localhost",):
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_loopback or ip.is_private
    except ValueError:
        pass
    try:
        ip = ipaddress.ip_address(socket.gethostbyname(host))
        return ip.is_loopback or ip.is_private
    except Exception:
        return False


def _doh_txt(name: str) -> list:
    """جلب سجلات TXT عبر DNS-over-HTTPS (بدون اعتماد على DNS محلي)."""
    values = []
    for base in DOH_RESOLVERS:
        try:
            r = requests.get(
                base, params={"name": name, "type": "TXT"},
                headers={"accept": "application/dns-json"}, timeout=10,
            )
            data = r.json()
            for ans in data.get("Answer", []):
                if ans.get("type") == 16:
                    values.append(ans.get("data", "").strip('"'))
            if values:
                break
        except Exception:
            continue
    return values


# ----------------------------------------------------------------------
# البوابة
# ----------------------------------------------------------------------
def verify_target(url: str, token: str, auth_domain: str = None) -> tuple:
    """يرجّع (authorized: bool, reason: str)."""
    host = urlparse(url).hostname or url
    if is_private(host):
        return True, "loopback/private — مملوك ذاتياً"
    domain = auth_domain or registrable(host)
    record = TXT_PREFIX + domain
    txts = _doh_txt(record)
    expected = f"megganew-verify={token}"
    if expected in txts:
        return True, f"تم التحقق عبر TXT {record}"
    return False, (
        f"لا يوجد تحقق ملكية. أضف سجل TXT:\n"
        f"    {record}  →  {expected}\n"
        f"الموجود حالياً: {txts or 'لا شيء'}"
    )


def load_scope(path: str) -> dict:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def authorized_targets(scope: dict) -> tuple:
    """
    يفلتر الأهداف المصرّح بها.
    scope = {"auth_token": "...", "targets": [{"url": "...", "auth_domain": "..."}]}
    يرجّع (allowed: list[str], rejected: list[tuple[str,str]]).
    """
    token = scope.get("auth_token", "")
    allowed, rejected = [], []
    for t in scope.get("targets", []):
        url = t["url"] if isinstance(t, dict) else t
        ad = t.get("auth_domain") if isinstance(t, dict) else None
        ok, reason = verify_target(url, token, ad)
        (allowed.append(url) if ok else rejected.append((url, reason)))
    return allowed, rejected


def authorized_hosts(allowed_urls) -> set:
    """أسماء المضيفين المتحقَّق منهم — تُمرَّر لعميل HTTP كبوابة."""
    return {urlparse(u).hostname for u in allowed_urls if urlparse(u).hostname}
