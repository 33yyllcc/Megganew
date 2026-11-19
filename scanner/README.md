# 🛰️ Megganew Scan — نظام فحص أمني مُسلسَل

نظام فحص أمني متكامل (framework) مبني كسلسلة وحدات، كل وحدة تاخذ مخرجات اللي قبلها.
صُمّم تنصبه وتشغّله بنفسك على **بنيتك المملوكة والمُتحقَّق منها** لفحص حماية تطبيقك.

```
 verification → recon → discover → authtest → extract → assess → report
   (التحقق)    (استطلاع) (اكتشاف)  (الدخول)  (السحب)   (تقييم)   (تقرير)
```

**بوابة التحقق تحكم كل شيء:** عميل HTTP يرفض أي طلب لهدف غير متحقَّق من ملكيته،
فلا تعمل أي وحدة قبل التحقق — بل تطلب منك التحقق أولاً.

---

## ⚖️ التصميم المسؤول (مهم)

الأداة قوية، فبُنيت بثلاث ضمانات تحميك:

1. **بوابة النطاق (Scope Guard):** ترفض فحص أي دومين إلا إذا أثبتّ ملكيته بسجل DNS TXT
   (`_megganew-pentest.<domain>`) — إلا عناوين loopback/الشبكة الخاصة (مملوكة ذاتياً).
   يعني **مستحيل** توجّهها على جهة ما تملكها بالغلط.
2. **غير مدمّرة:** تمنع تلقائياً الطرق المغيّرة للحالة (DELETE/PUT/PATCH) والمسارات
   الخطيرة (`erase`, `restore`, `run`, `logout`...). الفحوص الفعّالة تحتاج علم `--active`.
3. **إثبات لا سحب جماعي + تلطيف السرعة:** تجيب عيّنة إثبات محدودة الحجم، وتحدّ عدد
   الطلبات بالثانية حتى ما تؤذي خدمتك.

---

## 🧩 الوحدات (كل وحدة تغذّي التالية)

| # | الوحدة | شنو تسوي | المخرجات |
|---|--------|----------|----------|
| 0 | `verification` | **الملف الوحيد للتحقق** — إثبات ملكية الهدف (DNS TXT) | بوابة كل الطلبات |
| 1 | `recon` | تقرأ الهيدرز، تبصم التقنية، تحلّل رؤوس الأمان، TLS، DNS، كوكيز | معلومات كل هدف |
| 2 | `discover` | تستخرج نقاط API من ملفات JS + قائمة كلمات مسارات | قائمة نقاط النهاية |
| 3 | `authtest` | تجاوز الدخول: SQLi bypass، بيانات افتراضية، rate limiting، JWT | ثغرات مصادقة |
| 4 | `extract` | سحب البيانات: SQLi (error/boolean/UNION PoC)، IDOR | ثغرات سحب بيانات |
| 5 | `assess` | Access Control، Misconfig، CORS، XSS، ملفات مكشوفة | ثغرات عامة |
| 6 | `report` | تجمع الكل بتقرير Markdown + JSON بخطورة وتصنيف OWASP | `report.md` / `report.json` |

> `authtest` و `extract` فعّالتان — تحتاجان `--active`.
> راجع `../docs/DATA-EXTRACTION.md` لمرجع كل التقنيات.

المنسّق (`cli.py`) يربط السلسلة ويشغّلها بأمر واحد.

---

## 🚀 التنصيب والتشغيل

```bash
# من جذر المشروع
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cd scanner
```

### 1) جهّز ملف النطاق `scope.json`
```json
{
  "auth_token": "<التوكن الذي وضعته في سجل TXT>",
  "targets": [
    {"url": "https://admin.mazums.org", "auth_domain": "mazums.org"},
    {"url": "https://map.mazums.org",   "auth_domain": "mazums.org"}
  ]
}
```

### 2) أثبت الملكية (مرة واحدة لكل دومين)
أضف سجل DNS:
```
_megganew-pentest.mazums.org   TXT   megganew-verify=<التوكن نفسه>
```

### 3) تحقّق من النطاق (بدون فحص)
```bash
python -m megganew_scan.cli verify --scope scope.json
```

### 4) شغّل السلسلة الكاملة
```bash
# فحص آمن (استطلاع + اكتشاف + وصول + إعدادات)
python -m megganew_scan.cli run --scope scope.json --out output/

# مع الفحوص الفعّالة الكاشفة (XSS/SQLi indicators) — غير مدمّرة
python -m megganew_scan.cli run --scope scope.json --active --rate 2
```

### الخيارات
| الخيار | الوصف | الافتراضي |
|--------|-------|-----------|
| `--scope` | ملف النطاق JSON | (مطلوب) |
| `--out` | مجلد المخرجات | `output/` |
| `--rate` | أقصى طلبات/ثانية | `2.0` |
| `--active` | تفعيل فحوص الحقن الكاشفة | معطّل |
| `--max-bytes` | حجم عيّنة الإثبات | `20000` |

المخرجات تنحفظ في `output/scan-<تاريخ>/report.md` و `report.json`.

---

## 🧪 اختبارها بأمان

الأداة مُختبَرة على المختبر الهشّ المحلي (`../lab/app.py`) — شغّله واختبر عليها:

```bash
# نافذة 1
cd ../lab && python app.py
# نافذة 2
cd ../scanner
echo '{"auth_token":"x","targets":[{"url":"http://127.0.0.1:5000"}]}' > scope.local.json
python -m megganew_scan.cli run --scope scope.local.json --active --rate 20
```
(loopback مصرّح تلقائياً، فتشوف الأداة تلگى ثغرات المختبر وتطلّع تقرير.)

---

## 📐 شلون توسّعها

كل وحدة ملف مستقل في `megganew_scan/modules/`. تضيف فحص جديد = تضيف دالة بـ
`assess.py` ترجّع `_finding(...)`. تضيف مصدر اكتشاف = تعدّل `discover.py`. التقرير
يلتقط أي نتيجة تلقائياً.

> ⚠️ استخدمها **فقط** على أنظمة أثبتّ ملكيتها عبر البوابة، أو عندك عليها تفويض مكتوب.
