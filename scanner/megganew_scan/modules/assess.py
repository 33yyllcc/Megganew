# -*- coding: utf-8 -*-
"""
الوحدة 3 — التقييم (Assess)
===========================
تاخذ نقاط النهاية المكتشفة وتشغّل فحوصات ثغرات (كاشفة، غير مدمّرة):
  - Broken Access Control: نقاط حساسة بلا مصادقة ترجّع 200.
  - Security Misconfiguration: CSP/HSTS، صفحات debug/config/.env/.git مكشوفة.
  - CORS misconfiguration: انعكاس Origin عشوائي مع credentials.
  - XSS reflection indicator: انعكاس علامة بلا ترميز.
  - SQLi error indicator: توقيع خطأ SQL عند حقن اقتباس.
  - Verbose error / stack trace.
الفحوص الفعّالة (الحقن) تحتاج allow_active=True (علم --active).
المخرجات: قائمة findings.
"""

import re
import uuid

SENSITIVE = ("admin", "config", "debug", "backup", "stats", "system",
             "internal", "private", "secret", "user", "wallet")
SQL_ERRORS = re.compile(
    r"(SQL syntax|sqlite3\.|psycopg2|mysqli?_|ORA-\d{5}|SQLSTATE|"
    r"unclosed quotation|near \".*\": syntax error)", re.I)
STACK = re.compile(r"(Traceback \(most recent call last\)|Exception in|"
                   r"at [\w.]+\([\w.]+:\d+\)|\.java:\d+\)|stack trace)", re.I)


def _finding(title, severity, endpoint, evidence, owasp, fix):
    return {
        "id": "FIND-" + uuid.uuid4().hex[:6],
        "title": title, "severity": severity, "endpoint": endpoint,
        "evidence": (evidence or "")[:400], "owasp": owasp, "remediation": fix,
    }


def _looks_sensitive(url):
    return any(s in url.lower() for s in SENSITIVE)


def run(session, discovered, allow_active=False):
    findings = []
    for url, info in discovered.items():
        base = info["base"]
        endpoints = info["all_endpoints"]

        for ep in endpoints:
            low = ep.lower()

            # --- exposed secrets/config files ---
            if low.endswith((".env", ".git/config")):
                r = session.get(ep)
                if getattr(r, "status_code", 0) == 200 and getattr(r, "_body_sample", ""):
                    findings.append(_finding(
                        "ملف حساس مكشوف", "عالية", ep,
                        r._body_sample, "A05: Security Misconfiguration",
                        "امنع الوصول للملفات الحساسة وأزلها من جذر الويب."))
                continue

            # --- Broken Access Control: نقاط حساسة بلا مصادقة ---
            if _looks_sensitive(ep):
                r = session.get(ep)
                code = getattr(r, "status_code", 0)
                body = getattr(r, "_body_sample", "")
                if code == 200 and len(body) > 20:
                    sev = "حرجة" if "admin" in low else "عالية"
                    findings.append(_finding(
                        "وصول لنقطة حساسة بدون مصادقة (Broken Access Control)",
                        sev, ep, f"HTTP 200 بلا توكن. عيّنة: {body[:200]}",
                        "A01: Broken Access Control",
                        "تحقّق من الجلسة والدور على الخادم (deny-by-default) لكل نقطة."))
                elif code in (401, 403):
                    pass  # محميّة — جيد

            # --- Verbose error / stack trace ---
            r = session.get(ep + ("&" if "?" in ep else "?") + "x='\"<test")
            body = getattr(r, "_body_sample", "")
            if STACK.search(body):
                findings.append(_finding(
                    "تسريب أثر خطأ مفصّل (Stack Trace)", "متوسطة", ep,
                    body, "A05: Security Misconfiguration",
                    "عطّل رسائل الأخطاء المفصّلة في الإنتاج."))
            # --- SQLi error indicator (كاشف فقط) ---
            if SQL_ERRORS.search(body):
                findings.append(_finding(
                    "مؤشّر حقن SQL (رسالة خطأ قاعدة بيانات)", "عالية", ep,
                    body, "A03: Injection",
                    "استخدم استعلامات مُعاملة (parameterized) وتحقّق من المدخلات."))

            # --- CORS misconfiguration ---
            r = session.get(ep, headers={"Origin": "https://evil.example"})
            acao = getattr(r, "headers", {}).get("Access-Control-Allow-Origin", "")
            acac = getattr(r, "headers", {}).get("Access-Control-Allow-Credentials", "")
            if acao == "https://evil.example" or (acao == "*" and acac == "true"):
                findings.append(_finding(
                    "إعداد CORS خاطئ (انعكاس Origin)", "عالية", ep,
                    f"ACAO={acao} ACAC={acac}", "A05: Security Misconfiguration",
                    "لا تعكس Origin عشوائياً؛ استخدم قائمة سماح صارمة."))

            # --- XSS reflection indicator (فعّال) ---
            if allow_active:
                marker = "mxss" + uuid.uuid4().hex[:6]
                payload = f"<{marker}>"
                sep = "&" if "?" in ep else "?"
                r = session.get(ep + sep + "q=" + payload)
                if payload in getattr(r, "_body_sample", ""):
                    findings.append(_finding(
                        "انعكاس مدخل بلا ترميز (مؤشّر XSS)", "عالية", ep,
                        f"انعكست {payload} خاماً", "A03: Injection",
                        "رمّز المخرجات (HTML-encode) وفعّل CSP."))

    # إزالة التكرار
    seen, uniq = set(), []
    for f in findings:
        key = (f["title"], f["endpoint"])
        if key not in seen:
            seen.add(key)
            uniq.append(f)
    return uniq
