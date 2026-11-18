# -*- coding: utf-8 -*-
"""
عميل HTTP آمن ومشترك
=====================
- تلطيف السرعة (rate limiting) حتى لا نؤذي الخدمة.
- مهلة افتراضية لكل طلب.
- حارس غير مدمّر: يمنع الطرق المغيّرة للحالة والمسارات الخطيرة افتراضياً.
- تحديد حجم القراءة (عيّنة إثبات، لا سحب جماعي).
"""

import time
import threading
import requests

# مسارات/كلمات تدل على إجراء مدمّر أو مغيّر للحالة — تُمنع افتراضياً
DESTRUCTIVE_HINTS = (
    "erase", "delete", "destroy", "drop", "restore", "/run", "wipe",
    "reset", "backups/run", "backups/restore", "logout", "purge", "remove",
)
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
DEFAULT_UA = "megganew-scan/1.0 (authorized self-assessment)"


class Blocked(Exception):
    pass


class SafeSession:
    def __init__(self, rate=2.0, timeout=12, max_bytes=20000, allow_active=False):
        """
        rate: أقصى عدد طلبات بالثانية.
        max_bytes: أقصى حجم جسم يُقرأ (عيّنة إثبات).
        allow_active: السماح بطلبات POST/فحوص فعّالة غير مدمّرة.
        """
        self.min_interval = 1.0 / max(rate, 0.1)
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.allow_active = allow_active
        self._last = 0.0
        self._lock = threading.Lock()
        self._s = requests.Session()
        self._s.headers["User-Agent"] = DEFAULT_UA
        self.count = 0

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


class _Err:
    """بديل عند فشل الطلب حتى لا ينهار الـ pipeline."""
    status_code = 0
    headers = {}
    _body_sample = ""

    def __init__(self, err):
        self.error = err
