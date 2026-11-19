# -*- coding: utf-8 -*-
"""
عميل HTTP آمن ومشترك — مُقيّد ببوابة التحقق
=============================================
- بوابة تحقّق: لا يسمح بأي طلب إلا لمضيف تم إثبات ملكيته (verification.py).
- تلطيف السرعة (rate limiting) حتى لا نؤذي الخدمة.
- مهلة افتراضية لكل طلب.
- حارس غير مدمّر: يمنع الطرق المغيّرة للحالة والمسارات الخطيرة افتراضياً.
- تحديد حجم القراءة (عيّنة إثبات، لا سحب جماعي).

كل الوحدات (recon/discover/assess/authtest/extract) تمر عبر هذا العميل،
فلا تعمل أي وحدة على هدف غير متحقَّق منه — تطلب منك التحقق أولاً.
"""

import time
import threading
from urllib.parse import urlparse

import requests

from .verification import is_private  # بوابة التحقق — المصدر الوحيد

# مسارات/كلمات تدل على إجراء مدمّر أو مغيّر للحالة — تُمنع افتراضياً
DESTRUCTIVE_HINTS = (
    "erase", "delete", "destroy", "drop", "restore", "/run", "wipe",
    "reset", "backups/run", "backups/restore", "logout", "purge", "remove",
)
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
DEFAULT_UA = "megganew-scan/1.0 (authorized self-assessment)"


class Blocked(Exception):
    pass


class NotVerified(Exception):
    """يُرفع عندما يُطلب فحص هدف لم يُتحقَّق من ملكيته."""


class SafeSession:
    def __init__(self, authorized_hosts, rate=2.0, timeout=12,
                 max_bytes=20000, allow_active=False):
        """
        authorized_hosts: مجموعة أسماء المضيفين المتحقَّق منهم (من verification).
                          لا يُسمح بأي طلب خارجها (إلا loopback/شبكة خاصة).
        rate: أقصى عدد طلبات بالثانية.
        max_bytes: أقصى حجم جسم يُقرأ (عيّنة إثبات).
        allow_active: السماح بطلبات POST/فحوص فعّالة غير مدمّرة.
        """
        self.authorized_hosts = set(authorized_hosts or [])
        self.min_interval = 1.0 / max(rate, 0.1)
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.allow_active = allow_active
        self._last = 0.0
        self._lock = threading.Lock()
        self._s = requests.Session()
        self._s.headers["User-Agent"] = DEFAULT_UA
        self.count = 0

    # ---------- بوابة التحقق ----------
    def _check_verified(self, url):
        host = urlparse(url).hostname or ""
        if host in self.authorized_hosts:
            return
        if is_private(host):
            return
        raise NotVerified(
            f"⛔ الهدف «{host}» غير مُتحقَّق من ملكيته.\n"
            f"   سوِّ التحقق أولاً:  python -m megganew_scan.cli verify --scope <ملفك>\n"
            f"   (أضف سجل TXT للدومين قبل أي فحص.)"
        )

    def _throttle(self):
        with self._lock:
            wait = self.min_interval - (time.time() - self._last)
            if wait > 0:
                time.sleep(wait)
            self._last = time.time()

    def _guard(self, method, url):
        m = method.upper()
        low = url.lower()
        if any(h in low for h in DESTRUCTIVE_HINTS):
            raise Blocked(f"مُنع (مسار مدمّر محتمل): {url}")
        if m not in SAFE_METHODS and not self.allow_active:
            raise Blocked(f"مُنع (طريقة {m} تحتاج --active): {url}")
        if m in ("DELETE", "PUT", "PATCH"):
            raise Blocked(f"مُنع (طريقة مدمّرة {m}): {url}")

    def request(self, method, url, **kw):
        self._check_verified(url)     # ← البوابة قبل أي شيء
        self._guard(method, url)
        self._throttle()
        kw.setdefault("timeout", self.timeout)
        kw.setdefault("allow_redirects", False)
        try:
            r = self._s.request(method, url, stream=True, **kw)
            body = r.raw.read(self.max_bytes, decode_content=True) or b""
            r._body_sample = body.decode("utf-8", "replace")
            self.count += 1
            return r
        except requests.RequestException as e:
            return _Err(str(e))

    def get(self, url, **kw):
        return self.request("GET", url, **kw)

    def head(self, url, **kw):
        return self.request("HEAD", url, **kw)

    def post(self, url, **kw):
        return self.request("POST", url, **kw)


class _Err:
    """بديل عند فشل الطلب حتى لا ينهار الـ pipeline."""
    status_code = 0
    headers = {}
    _body_sample = ""

    def __init__(self, err):
        self.error = err
