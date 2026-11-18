# -*- coding: utf-8 -*-
"""
الوحدة 2 — الاكتشاف (Discover)
==============================
تاخذ مخرجات recon وتكتشف سطح الهجوم:
  - تستخرج روابط ملفات JS من الصفحة، وتحمّلها، وتستخرج مسارات/نقاط API منها.
  - تجرّب قائمة كلمات صغيرة لاكتشاف مسارات شائعة (مُلطّفة).
المخرجات: قائمة نقاط النهاية المكتشفة لكل هدف → تُغذّي assess.
"""

import os
import re
from urllib.parse import urljoin, urlparse

_WL_FILE = os.path.join(os.path.dirname(__file__), "..", "data", "wordlist.txt")


def _load_wordlist():
    paths = list(COMMON_PATHS)
    try:
        with open(_WL_FILE, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and line not in paths:
                    paths.append(line)
    except OSError:
        pass
    return paths

JS_SRC = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)
# مسارات مثل '/api/v1/...'، '/admin/...'
PATH_RE = re.compile(r'["\'](/[a-zA-Z0-9_\-/.]{2,60})["\']')
API_BASE = re.compile(r'(?:API|BASE|baseUrl|apiBase)\s*[:=]\s*["\']([^"\']+)["\']')

COMMON_PATHS = [
    "/", "/robots.txt", "/sitemap.xml", "/.git/config", "/.env",
    "/config", "/debug", "/status", "/health", "/api", "/api/v1",
    "/admin", "/login", "/backup", "/server-status", "/.well-known/security.txt",
]


def _extract_from_js(text):
    paths = set(PATH_RE.findall(text))
    bases = set(API_BASE.findall(text))
    # صفّي الضوضاء (ملفات ثابتة)
    paths = {p for p in paths
             if not re.search(r'\.(png|jpe?g|webp|svg|css|js|ico|woff2?)$', p, re.I)}
    return paths, bases


def run(session, recon_results, wordlist=None):
    discovered = {}
    for url, info in recon_results.items():
        p = urlparse(url)
        base = f"{p.scheme}://{p.netloc}"   # netloc يحافظ على المنفذ (host:port)
        endpoints = set()
        api_bases = set()

        # 1) ملفات JS المرتبطة بالصفحة
        body = info.get("body_sample", "")
        for src in JS_SRC.findall(body):
            js_url = urljoin(url, src)
            if urlparse(js_url).hostname != urlparse(url).hostname:
                continue  # ابقَ داخل نفس الأصل
            r = session.get(js_url)
            text = getattr(r, "_body_sample", "")
            paths, bases = _extract_from_js(text)
            endpoints |= paths
            api_bases |= bases

        # 2) قائمة كلمات مسارات شائعة (مُلطّفة)
        wl = wordlist or _load_wordlist()
        probe = {}
        for p in wl:
            r = session.get(base + p)
            code = getattr(r, "status_code", 0)
            if code and code not in (404, 0):
                probe[p] = code

        # 3) ادمج نقاط API (base + path)
        full = set()
        for b in (api_bases or {""}):
            for ep in endpoints:
                if ep.startswith(b) or not b:
                    full.add(base + ep if ep.startswith("/") else base + "/" + ep)
        full |= {base + p for p in probe}

        discovered[url] = {
            "base": base,
            "api_bases": sorted(api_bases),
            "endpoints_from_js": sorted(endpoints),
            "probe_hits": probe,
            "all_endpoints": sorted(full),
        }
    return discovered
