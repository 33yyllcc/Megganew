# -*- coding: utf-8 -*-
"""
Megganew Scan — المنسّق (Orchestrator)
======================================
يربط الوحدات في سلسلة واحدة:

   scope-guard → recon → discover → assess → report

كل وحدة تاخذ مخرجات اللي قبلها. يشتغل فقط على أهداف مُتحقَّق من ملكيتها.

التشغيل:
   python -m megganew_scan.cli run --scope scope.json --out output/
   python -m megganew_scan.cli run --scope scope.json --active   # يفعّل فحوص الحقن
"""

import argparse
import json
import os
import sys
from datetime import datetime

from . import scope as scope_mod
from .httpclient import SafeSession
from .modules import recon, discover, assess, report


def _load_scope(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def cmd_run(args):
    sc = _load_scope(args.scope)

    print("══════════════════════════════════════════════════")
    print(" Megganew Scan — بوابة النطاق (Scope Guard)")
    print("══════════════════════════════════════════════════")
    allowed, rejected = scope_mod.authorized_targets(sc)
    for url, reason in rejected:
        print(f"  ⛔ مرفوض: {url}\n     {reason}")
    for url in allowed:
        print(f"  ✅ مصرّح: {url}")
    if not allowed:
        print("\nلا أهداف مصرّح بها. أضف سجلات التحقق أولاً. توقّف.")
        return 1
    print()

    session = SafeSession(rate=args.rate, timeout=args.timeout,
                          max_bytes=args.max_bytes, allow_active=args.active)

    print("▶ [1/4] الاستطلاع (recon)…")
    recon_out = recon.run(session, allowed)

    print("▶ [2/4] الاكتشاف (discover)…")
    disc_out = discover.run(session, recon_out)
    n_ep = sum(len(d["all_endpoints"]) for d in disc_out.values())
    print(f"    نقاط مكتشفة: {n_ep}")

    print("▶ [3/4] التقييم (assess)" + (" [+active]" if args.active else "") + "…")
    findings = assess.run(session, disc_out, allow_active=args.active)
    print(f"    نتائج: {len(findings)}")

    print("▶ [4/4] التقرير (report)…")
    outdir = os.path.join(args.out, datetime.now().strftime("scan-%Y%m%d-%H%M%S"))
    meta = {"targets": allowed, "requests": session.count,
            "active": args.active, "rate": args.rate}
    md = report.run(outdir, recon_out, disc_out, findings, meta)

    print(f"\n✅ انتهى. إجمالي الطلبات: {session.count}")
    print(f"   التقرير: {md}")
    print(f"   JSON:    {os.path.join(outdir, 'report.json')}")
    # ملخص سريع
    from collections import Counter
    c = Counter(f["severity"] for f in findings)
    if c:
        print("   ملخص: " + " | ".join(f"{k}:{v}" for k, v in c.items()))
    return 0


def cmd_verify(args):
    """تحقّق فقط من ملكية الأهداف بدون فحص."""
    sc = _load_scope(args.scope)
    allowed, rejected = scope_mod.authorized_targets(sc)
    for url in allowed:
        print(f"✅ {url}")
    for url, reason in rejected:
        print(f"⛔ {url} — {reason}")
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="megganew-scan",
                                description="أداة فحص أمني مسؤولة لبنية مملوكة ذاتياً")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="تشغيل السلسلة الكاملة")
    r.add_argument("--scope", required=True, help="ملف النطاق JSON")
    r.add_argument("--out", default="output", help="مجلد المخرجات")
    r.add_argument("--rate", type=float, default=2.0, help="أقصى طلبات/ثانية")
    r.add_argument("--timeout", type=int, default=12)
    r.add_argument("--max-bytes", type=int, default=20000, help="حجم عيّنة الإثبات")
    r.add_argument("--active", action="store_true",
                   help="تفعيل فحوص الحقن الكاشفة (غير مدمّرة)")
    r.set_defaults(func=cmd_run)

    v = sub.add_parser("verify", help="تحقّق من ملكية الأهداف فقط")
    v.add_argument("--scope", required=True)
    v.set_defaults(func=cmd_verify)

    args = p.parse_args(argv)
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
