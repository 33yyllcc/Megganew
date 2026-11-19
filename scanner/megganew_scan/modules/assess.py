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

# قائمة أوسع لملفات حساسة شائعة: أسرار، نسخ احتياطية، إعدادات، خرائط مصدر.
# كل عنصر: (المسار, الخطورة, الوصف). الفحص إثباتي فقط — عيّنة محدودة لا تنزيل كامل.
EXPOSED_FILE_PATHS = [
    (".env", "حرجة", "متغيرات بيئة (غالباً تحتوي أسرار/مفاتيح)"),
    (".env.local", "حرجة", "متغيرات بيئة محلية"),
    (".env.production", "حرجة", "متغيرات بيئة إنتاج"),
    (".git/config", "عالية", "إعداد مستودع Git (قد يسمح باستنساخ الكود كاملاً)"),
    (".git/HEAD", "عالية", "مؤشر على مستودع .git مكشوف بجذر الويب"),
    (".svn/entries", "عالية", "مستودع SVN مكشوف"),
    ("wp-config.php", "حرجة", "إعداد ووردبريس (بيانات اتصال قاعدة بيانات)"),
    ("config.json", "عالية", "ملف إعداد عام"),
    ("config.yml", "عالية", "ملف إعداد عام (YAML)"),
    ("docker-compose.yml", "متوسطة", "إعداد Docker (قد يكشف بنية الخدمات/منافذ)"),
    ("Dockerfile", "منخفضة", "ملف بناء الحاوية"),
    ("package.json", "منخفضة", "يكشف تبعيات/إصدار المشروع"),
    ("composer.json", "منخفضة", "يكشف تبعيات PHP"),
    ("backup.zip", "عالية", "نسخة احتياطية مضغوطة محتملة"),
    ("backup.sql", "حرجة", "تفريغ قاعدة بيانات محتمل"),
    ("database.sql", "حرجة", "تفريغ قاعدة بيانات محتمل"),
    ("dump.sql", "حرجة", "تفريغ قاعدة بيانات محتمل"),
    ("app.js.map", "متوسطة", "خريطة مصدر (تكشف الكود المصدري الأصلي)"),
    ("main.js.map", "متوسطة", "خريطة مصدر (تكشف الكود المصدري الأصلي)"),
    ("bundle.js.map", "متوسطة", "خريطة مصدر (تكشف الكود المصدري الأصلي)"),
    (".DS_Store", "منخفضة", "يكشف أسماء ملفات/مجلدات الخادم"),
    ("phpinfo.php", "عالية", "يكشف تفاصيل بيئة PHP بالكامل"),
    ("server-status", "متوسطة", "حالة خادم Apache (قد تكشف IPs/طلبات حيّة)"),
    ("id_rsa", "حرجة", "مفتاح SSH خاص محتمل"),
    (".ssh/id_rsa", "حرجة", "مفتاح SSH خاص محتمل"),
    ("credentials.json", "حرجة", "ملف اعتمادات"),
    (".htpasswd", "عالية", "هاشات كلمات سر HTTP Basic Auth"),
]
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


def _file_exposure_sweep(session, base, findings):
    """يفحص قائمة واسعة من الملفات الحساسة الشائعة على جذر الموقع.
    كل فحص GET واحد، عيّنة إثبات محدودة فقط — لا تنزيل كامل لأي ملف."""
    for path, severity, desc in EXPOSED_FILE_PATHS:
        r = session.get(base.rstrip("/") + "/" + path, isolate_cookies=True)
        code = getattr(r, "status_code", 0)
        body = getattr(r, "_body_sample", "")
        if code == 200 and body.strip() and "<html" not in body.lower()[:200]:
            findings.append(_finding(
                f"ملف حساس مكشوف: {path}", severity, base + "/" + path,
                f"{desc}. عيّنة: {body[:200]}",
                "A05: Security Misconfiguration / A01 (Sensitive Data Exposure)",
                "امنع الوصول لهذا الملف من إعدادات الخادم، وأزله من جذر الويب "
                "إن لم يكن ضرورياً للتشغيل العام."))


def run(session, discovered, allow_active=False):
    findings = []
    for url, info in discovered.items():
        base = info["base"]
        endpoints = info["all_endpoints"]

        _file_exposure_sweep(session, base, findings)

        for ep in endpoints:
            low = ep.lower()

            # --- exposed secrets/config files ---
            if low.endswith((".env", ".git/config")):
                r = session.get(ep, isolate_cookies=True)
                if getattr(r, "status_code", 0) == 200 and getattr(r, "_body_sample", ""):
                    findings.append(_finding(
                        "ملف حساس مكشوف", "عالية", ep,
                        r._body_sample, "A05: Security Misconfiguration",
                        "امنع الوصول للملفات الحساسة وأزلها من جذر الويب."))
                continue

            # --- Broken Access Control: نقاط حساسة بلا مصادقة ---
            if _looks_sensitive(ep):
                r = session.get(ep, isolate_cookies=True)
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
            r = session.get(ep + ("&" if "?" in ep else "?") + "x='\"<test", isolate_cookies=True)
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
            r = session.get(ep, headers={"Origin": "https://evil.example"}, isolate_cookies=True)
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
                r = session.get(ep + sep + "q=" + payload, isolate_cookies=True)
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
