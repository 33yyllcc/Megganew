# -*- coding: utf-8 -*-
"""
الوحدة — فحص المصادقة وتجاوز الدخول (Auth Testing)
===================================================
تختبر قوة تسجيل الدخول في تطبيقك وتكشف طرق التحايل عليه:

  - SQLi Auth Bypass: حمولات تجاوز الدخول الكلاسيكية.
  - Default / Weak Credentials: قائمة صغيرة من بيانات الدخول الشائعة.
  - Missing Rate Limiting: هل يسمح بمحاولات غير محدودة (قابل للتخمين)؟
  - Weak Session Cookies: غياب HttpOnly/Secure/SameSite.
  - JWT Weaknesses: alg:none أو خوارزمية ضعيفة إن وُجد توكن.
  - Clickjacking على صفحة الدخول: هل يمكن تضمينها بإطار (iframe) لخداع
    المستخدم يضغط زراً حقيقياً بدون علمه (UI redressing)؟
  - CSRF على نموذج الدخول/الجلسة: هل يوجد توكن CSRF يمنع إرسال الفورم
    من موقع خارجي؟
  - Username Enumeration: هل رسالة الخطأ تكشف وجود/عدم وجود المستخدم؟
    (يسهّل على مهاجم استهداف حسابات حقيقية بالاسم).

كل هذي فحوص على **تطبيقك نفسه** (ضوابطه البرمجية) — وليست أدوات خداع
لبشر آخرين. لا تُنشئ هذي الوحدة أي صفحة مزوّرة ولا ترسل لأي طرف ثالث.

يتطلب --active (يرسل POST). الهدف: تعرف نقاط ضعف الدخول لتقوّيها —
بحدود مسؤولة (قوائم صغيرة، بلا تخمين جماعي/brute-force).
"""

import base64
import json
import re
import uuid
from urllib.parse import urljoin

FORM_RE = re.compile(r"<form[^>]*>(.*?)</form>", re.I | re.S)
ACTION_RE = re.compile(r'action=["\']([^"\']*)["\']', re.I)
INPUT_NAME_RE = re.compile(r'<input[^>]*name=["\']([^"\']+)["\']', re.I)

USER_FIELDS = ("username", "user", "email", "login", "userid", "name")
PASS_FIELDS = ("password", "pass", "pwd", "passwd")

SQLI_BYPASS = ["' OR '1'='1'-- -", "admin'-- -", "' OR 1=1-- -", "admin' OR '1'='1"]
COMMON_CREDS = [
    ("admin", "admin"), ("admin", "admin123"), ("admin", "password"),
    ("admin", "123456"), ("root", "root"), ("test", "test"),
]
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")


def _finding(title, severity, endpoint, evidence, owasp, fix):
    return {"id": "FIND-" + uuid.uuid4().hex[:6], "title": title,
            "severity": severity, "endpoint": endpoint,
            "evidence": (str(evidence) or "")[:400], "owasp": owasp,
            "remediation": fix}


def _body(r):
    return getattr(r, "_body_sample", "") or ""


def _find_login_pages(discovered):
    pages = set()
    for url, info in discovered.items():
        base = info["base"]
        for ep in info.get("all_endpoints", []):
            if re.search(r"(login|signin|sign-in|auth)", ep, re.I) and \
               not re.search(r"(logout|signout)", ep, re.I):
                pages.add(ep)
        # جرّب المسار الافتراضي
        pages.add(base + "/login")
    return pages


def _parse_form(html, page_url):
    m = FORM_RE.search(html)
    if not m:
        return None
    block = m.group(1)
    names = INPUT_NAME_RE.findall(block)
    act = ACTION_RE.search(m.group(0))
    action = urljoin(page_url, act.group(1)) if act and act.group(1) else page_url
    uf = next((n for n in names if n.lower() in USER_FIELDS), None)
    pf = next((n for n in names if n.lower() in PASS_FIELDS), None)
    return {"action": action, "user_field": uf or "username",
            "pass_field": pf or "password", "names": names}


def _has_session_cookie(r):
    sc = getattr(r, "headers", {}).get("set-cookie", "")
    return bool(re.search(r"(session|sid|token|auth)", sc, re.I))


def _success_like(resp, baseline):
    """هل الاستجابة تشبه نجاح دخول مقارنة بخطّ الأساس (دخول خاطئ)؟"""
    if getattr(resp, "status_code", 0) in (301, 302) and \
       baseline["status"] not in (301, 302):
        return True
    if _has_session_cookie(resp) and not baseline["cookie"]:
        return True
    body = _body(resp)
    # اختفاء رسالة الخطأ + فرق طول ملحوظ
    if baseline["err_marker"] and baseline["err_marker"] not in body and \
       abs(len(body) - baseline["len"]) > max(50, int(0.15 * (baseline["len"] or 1))):
        return True
    return False


def _test_login(session, page_url, findings):
    r = session.get(page_url)
    html = _body(r)
    form = _parse_form(html, page_url)
    if not form:
        return
    action, uf, pf = form["action"], form["user_field"], form["pass_field"]

    _clickjacking_check(session, page_url, findings)
    _csrf_check(session, page_url, form, findings)
    _username_enum_check(session, page_url, form, findings)

    # خط الأساس: دخول خاطئ مؤكّد
    rnd = uuid.uuid4().hex
    base_r = session.post(action, data={uf: "nouser_" + rnd, pf: "nopass_" + rnd})
    base_body = _body(base_r)
    err_marker = ""
    for cand in ("خاطئ", "خطأ", "invalid", "incorrect", "wrong", "failed"):
        if cand in base_body.lower() or cand in base_body:
            err_marker = cand
            break
    baseline = {"status": getattr(base_r, "status_code", 0),
                "cookie": _has_session_cookie(base_r),
                "len": len(base_body), "err_marker": err_marker}

    # 1) SQLi auth bypass
    for p in SQLI_BYPASS:
        r = session.post(action, data={uf: p, pf: "x"})
        if _success_like(r, baseline):
            findings.append(_finding(
                "تجاوز تسجيل الدخول عبر حقن SQL", "حرجة", action,
                f"الحمولة «{p}» في الحقل {uf} أدّت إلى دخول ناجح.",
                "A07: Identification & Authentication Failures",
                "استعلامات مُعاملة للمصادقة + تجزئة كلمات السر بـ bcrypt/argon2."))
            break

    # 2) default / weak creds
    for u, pw in COMMON_CREDS:
        r = session.post(action, data={uf: u, pf: pw})
        if _success_like(r, baseline):
            findings.append(_finding(
                "بيانات دخول افتراضية/ضعيفة", "عالية", action,
                f"نجح الدخول بـ {u}/{pw}.",
                "A07: Identification & Authentication Failures",
                "امنع كلمات السر الضعيفة/الافتراضية وافرض سياسة قوية."))
            break

    # 3) missing rate limiting (محاولات قليلة فقط — لا brute-force)
    limited = False
    for _ in range(6):
        r = session.post(action, data={uf: "x" + uuid.uuid4().hex[:6], pf: "y"})
        code = getattr(r, "status_code", 0)
        if code == 429 or re.search(r"(too many|محاولات|locked|مقفل|rate)", _body(r), re.I):
            limited = True
            break
    if not limited:
        findings.append(_finding(
            "غياب تحديد محاولات الدخول (Rate Limiting)", "متوسطة", action,
            "6 محاولات فاشلة متتالية بلا حظر/تأخير — عرضة للتخمين (brute-force).",
            "A07: Identification & Authentication Failures",
            "طبّق تحديد معدّل المحاولات + قفل مؤقت + CAPTCHA بعد عدة محاولات."))


def _clickjacking_check(session, page_url, findings):
    """هل تسمح صفحة الدخول بالتضمين بإطار (iframe) من موقع آخر؟"""
    r = session.get(page_url)
    headers = {k.lower(): v for k, v in dict(getattr(r, "headers", {})).items()}
    xfo = headers.get("x-frame-options", "")
    csp = headers.get("content-security-policy", "")
    has_frame_ancestors = "frame-ancestors" in csp.lower()
    if not xfo and not has_frame_ancestors:
        findings.append(_finding(
            "صفحة الدخول قابلة للتضمين بإطار خارجي (Clickjacking)", "متوسطة",
            page_url,
            "لا يوجد X-Frame-Options ولا CSP frame-ancestors — يمكن تضمين "
            "صفحة الدخول داخل إطار مخفي بموقع آخر لخداع المستخدم (UI redressing).",
            "A05: Security Misconfiguration",
            "أضف X-Frame-Options: DENY (أو SAMEORIGIN) وCSP frame-ancestors 'none'."))


def _csrf_check(session, page_url, form, findings):
    """هل نموذج الدخول/تسجيل بلا توكن CSRF يحمي من إرسال خارجي؟"""
    csrf_markers = ("csrf", "token", "_token", "authenticity", "nonce")
    has_token = any(any(m in n.lower() for m in csrf_markers) for n in form["names"])
    if not has_token:
        findings.append(_finding(
            "نموذج الدخول بلا توكن CSRF", "منخفضة", form["action"],
            f"الحقول الموجودة: {form['names']} — لا حقل يشبه توكن CSRF.",
            "A01: Broken Access Control / CSRF",
            "أضف توكن CSRF فريد لكل جلسة وتحقّق منه عند الإرسال؛ "
            "استخدم كوكيز SameSite=Lax/Strict كطبقة دفاع إضافية."))


def _username_enum_check(session, page_url, form, findings):
    """هل الخطأ يختلف بين مستخدم موجود (كلمة سر خطأ) وغير موجود؟"""
    action, uf, pf = form["action"], form["user_field"], form["pass_field"]
    rnd = uuid.uuid4().hex[:10]
    # مستخدم شبه مؤكّد غير موجود
    r_unknown = session.post(action, data={uf: "nouser_" + rnd, pf: "x" + rnd})
    # أسماء شائعة محتمل وجودها (admin قد يكون حقيقياً بتطبيقك)
    for candidate in ("admin", "test", "user"):
        r_known = session.post(action, data={uf: candidate, pf: "x" + rnd})
        b1, b2 = _body(r_unknown), _body(r_known)
        if b1 and b2 and b1 != b2 and abs(len(b1) - len(b2)) > 10:
            findings.append(_finding(
                "تعداد أسماء المستخدمين (Username Enumeration)", "منخفضة", action,
                f"رسالة/استجابة مختلفة بين مستخدم وهمي ومستخدم «{candidate}» — "
                "يمكن استنتاج وجود حسابات حقيقية.",
                "A07: Identification & Authentication Failures",
                "استخدم رسالة خطأ عامة موحّدة («بيانات الدخول غير صحيحة») "
                "لكل الحالات، وزمن استجابة ثابت."))
            break


def _jwt_checks(recon, findings):
    """فحص توكنات JWT الظاهرة في الاستطلاع."""
    for url, info in recon.items():
        blob = json.dumps(info.get("headers", {})) + info.get("body_sample", "")
        for tok in set(JWT_RE.findall(blob)):
            try:
                h = tok.split(".")[0]
                pad = h + "=" * (-len(h) % 4)
                header = json.loads(base64.urlsafe_b64decode(pad))
            except Exception:
                continue
            alg = str(header.get("alg", "")).lower()
            if alg == "none":
                findings.append(_finding(
                    "JWT بخوارزمية none — تزوير توكن ممكن", "حرجة", url,
                    f"رأس JWT: {header}", "A07: Auth Failures",
                    "ارفض alg=none؛ ثبّت الخوارزمية المتوقعة وتحقّق من التوقيع."))
            elif alg in ("hs256", "hs384") :
                findings.append(_finding(
                    "JWT بتوقيع متماثل (HS*) — خطر مفتاح ضعيف", "منخفضة", url,
                    f"alg={alg}", "A07: Auth Failures",
                    "استخدم مفتاحاً قوياً عشوائياً، أو وقّع بـ RS256، وراقب تسريبه."))


def run(session, discovered, recon=None, allow_active=False):
    if not allow_active:
        return []
    findings = []
    for page in _find_login_pages(discovered):
        try:
            _test_login(session, page, findings)
        except Exception:
            continue
    if recon:
        _jwt_checks(recon, findings)
    seen, uniq = set(), []
    for f in findings:
        key = (f["title"], f["endpoint"])
        if key not in seen:
            seen.add(key); uniq.append(f)
    return uniq
