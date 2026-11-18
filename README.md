# 🛡️ Megganew — Security Training Lab

بيئة تدريب محلية لتعلّم اختبار الاختراق عملياً، مع قوالب مشروع فحص احترافية.

> ⚠️ **تحذير:** `lab/app.py` تطبيق هشّ **عمداً**. شغّله محلياً فقط (`127.0.0.1`).
> لا ترفعه على أي سيرفر عام ولا تعرّضه للإنترنت.

---

## المحتويات

| المجلد/الملف | الوصف |
|--------------|-------|
| `GUIDE.md` | 📘 دليل النظام الكامل — ابدأ من هنا |
| `lab/app.py` | التطبيق الهشّ (14 ثغرة، كل وحدة معلّمة بالكود) |
| `docs/METHODOLOGY.md` | منهجية OWASP + تشك ليست الفحص |
| `docs/EXERCISES.md` | شرح + استغلال + إصلاح لكل ثغرة |
| `engagement/` | قوالب مشروع فحص حقيقي (نطاق، تقرير، تقدّم، ثغرات) |

## التشغيل السريع

```bash
python3 -m venv .venv
source .venv/bin/activate        # ويندوز: .venv\Scripts\activate
pip install -r requirements.txt
cd lab && python app.py
# افتح: http://127.0.0.1:5000
```

## الثغرات المغطّاة (14)

SQL Injection (login + UNION) · Reflected XSS · Stored XSS · Broken Authentication ·
IDOR · Missing Access Control · CSRF · Sensitive Data Exposure · SSRF ·
Command Injection · Path Traversal · SSTI · Insecure File Upload

## الاستخدام المسؤول

المهارات هنا للتعلّم. طبّقها **فقط** على أنظمة عندك عليها **تفويض مكتوب وموثّق**
وضمن النطاق المتفق عليه. راجع `GUIDE.md` و `engagement/SCOPE.md`.
