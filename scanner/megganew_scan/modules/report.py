# -*- coding: utf-8 -*-
"""
الوحدة 4 — التقرير (Report)
===========================
تجمع كل المخرجات (recon + discover + assess) في:
  - تقرير Markdown جاهز للتسليم.
  - ملف JSON كامل (للأرشفة/المعالجة).
"""

import json
import os
from datetime import datetime

SEV_ORDER = {"حرجة": 0, "عالية": 1, "متوسطة": 2, "منخفضة": 3, "معلوماتية": 4}
SEV_EMOJI = {"حرجة": "🔴", "عالية": "🟠", "متوسطة": "🟡", "منخفضة": "🔵", "معلوماتية": "⚪"}


def _counts(findings):
    c = {}
    for f in findings:
        c[f["severity"]] = c.get(f["severity"], 0) + 1
    return c


def run(outdir, recon, discovered, findings, meta=None):
    os.makedirs(outdir, exist_ok=True)
    meta = meta or {}
    ts = datetime.now().strftime("%Y-%m-%d %H:%M")
    findings = sorted(findings, key=lambda f: SEV_ORDER.get(f["severity"], 9))
    counts = _counts(findings)

    # JSON كامل
    full = {"generated": ts, "meta": meta, "recon": recon,
            "discovered": discovered, "findings": findings}
    with open(os.path.join(outdir, "report.json"), "w", encoding="utf-8") as f:
        json.dump(full, f, ensure_ascii=False, indent=2)

    # Markdown
    lines = []
    lines.append(f"# 🧾 تقرير فحص أمني — Megganew Scan\n")
    lines.append(f"- **التاريخ:** {ts}")
    lines.append(f"- **الأهداف:** {', '.join(recon.keys())}")
    lines.append(f"- **إجمالي الطلبات:** {meta.get('requests','?')}\n")

    lines.append("## ملخص النتائج\n")
    lines.append("| الخطورة | العدد |")
    lines.append("|---------|-------|")
    for sev in SEV_ORDER:
        if counts.get(sev):
            lines.append(f"| {SEV_EMOJI[sev]} {sev} | {counts[sev]} |")
    if not findings:
        lines.append("| — | لا توجد نتائج |")
    lines.append("")

    lines.append("## النتائج التفصيلية\n")
    if not findings:
        lines.append("_لم تُكتشف ثغرات بالفحوص المطبّقة. (لا يعني خلوّه تماماً — راجع يدوياً.)_\n")
    for f in findings:
        lines.append(f"### {SEV_EMOJI.get(f['severity'],'')} {f['id']} — {f['title']}")
        lines.append(f"- **الخطورة:** {f['severity']}")
        lines.append(f"- **النقطة:** `{f['endpoint']}`")
        lines.append(f"- **التصنيف:** {f['owasp']}")
        lines.append(f"- **الدليل:**\n```\n{f['evidence']}\n```")
        lines.append(f"- **الإصلاح:** {f['remediation']}\n")

    lines.append("## معلومات الاستطلاع (ملخص)\n")
    for url, info in recon.items():
        lines.append(f"### {url}")
        lines.append(f"- الحالة: {info.get('status')} | التقنية: {', '.join(info.get('server_tech') or []) or '—'}")
        miss = [m['header'] for m in info.get('missing_security_headers', [])]
        lines.append(f"- رؤوس أمان ناقصة: {', '.join(miss) or 'لا شيء'}\n")

    lines.append("---\n> أُنتج بأداة Megganew Scan على بنية مملوكة ذاتياً ومُتحقَّق منها. "
                 "للاستخدام المصرّح به فقط.")

    md_path = os.path.join(outdir, "report.md")
    with open(md_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return md_path
