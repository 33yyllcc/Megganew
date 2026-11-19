# -*- coding: utf-8 -*-
"""
Megganew Scan — المنسّق (Orchestrator)
======================================
يربط الوحدات في سلسلة واحدة، خلف بوابة التحقق:

   verification → recon → discover → authtest → extract → assess → report

التحقق أولاً دائماً. أي وحدة تُشغَّل على هدف غير متحقَّق منه تتوقف وتطلب التحقق.

التشغيل:
   python -m megganew_scan.cli verify --scope scope.json
   python -m megganew_scan.cli run    --scope scope.json --out output/
   python -m megganew_scan.cli run    --scope scope.json --active   # فحوص سحب البيانات/الدخول
"""

import argparse
import os
import sys
from collections import Counter
from datetime import datetime

from . import verification as vf
from .httpclient import SafeSession
from .modules import recon, discover, authtest, extract, assess, report


def _gate(scope_path):
    """بوابة التحقق — تُشغَّل قبل أي فحص. ترجّع (allowed, hosts) أو تنهي."""
    sc = vf.load_scope(scope_path)
    print("══════════════════════════════════════════════════")
    print(" بوابة التحقق (Verification Gate)")
    print("══════════════════════════════════════════════════")
    allowed, rejected = vf.authorized_targets(sc)
    for url, reason in rejected:
        print(f"  ⛔ مرفوض: {url}\n     {reason}")
    for url in allowed:
        print(f"  ✅ متحقَّق: {url}")
    if not allowed:
        print("\n⚠️  لا أهداف متحقَّق منها. سوِّ التحقق أولاً (أضف سجل TXT). توقّف.")
        return None, None
    print()
    return allowed, vf.authorized_hosts(allowed)


def cmd_verify(args):
    allowed, _ = _gate(args.scope)
    return 0 if allowed else 1


def cmd_run(args):
    allowed, hosts = _gate(args.scope)
    if not allowed:
        return 1

    session = SafeSession(authorized_hosts=hosts, rate=args.rate,
                          timeout=args.timeout, max_bytes=args.max_bytes,
                          allow_active=args.active)

    print("▶ [1/6] الاستطلاع (recon)…")
    recon_out = recon.run(session, allowed)

    print("▶ [2/6] الاكتشاف (discover)…")
    disc_out = discover.run(session, recon_out)
    n_ep = sum(len(d["all_endpoints"]) for d in disc_out.values())
    print(f"    نقاط مكتشفة: {n_ep}")

    tag = " [+active]" if args.active else " (آمن — بلا فحوص فعّالة؛ استخدم --active)"
    print(f"▶ [3/6] فحص المصادقة وتجاوز الدخول (authtest){tag}…")
    auth_findings = authtest.run(session, disc_out, recon=recon_out,
                                 allow_active=args.active)
    print(f"    نتائج: {len(auth_findings)}")

    print(f"▶ [4/6] سحب البيانات (extract){tag}…")
    ext_findings = extract.run(session, disc_out, allow_active=args.active)
    print(f"    نتائج: {len(ext_findings)}")

    print("▶ [5/6] التقييم العام (assess)…")
    gen_findings = assess.run(session, disc_out, allow_active=args.active)
    print(f"    نتائج: {len(gen_findings)}")

    findings = auth_findings + ext_findings + gen_findings

    print("▶ [6/6] التقرير (report)…")
    outdir = os.path.join(args.out, datetime.now().strftime("scan-%Y%m%d-%H%M%S"))
    meta = {"targets": allowed, "requests": session.count,
            "active": args.active, "rate": args.rate}
    md = report.run(outdir, recon_out, disc_out, findings, meta)

    print(f"\n✅ انتهى. إجمالي الطلبات: {session.count}")
    print(f"   التقرير: {md}")
    print(f"   JSON:    {os.path.join(outdir, 'report.json')}")
    c = Counter(f["severity"] for f in findings)
    if c:
        print("   ملخص: " + " | ".join(f"{k}:{v}" for k, v in c.items()))
    else:
        print("   لا نتائج (جرّب --active لتفعيل فحوص الدخول وسحب البيانات).")
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="megganew-scan",
        description="أداة فحص أمني مسؤولة لبنية مملوكة ذاتياً (خلف بوابة تحقق)")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="تشغيل السلسلة الكاملة (بعد التحقق)")
    r.add_argument("--scope", required=True, help="ملف النطاق JSON")
    r.add_argument("--out", default="output", help="مجلد المخرجات")
    r.add_argument("--rate", type=float, default=2.0, help="أقصى طلبات/ثانية")
    r.add_argument("--timeout", type=int, default=12)
    r.add_argument("--max-bytes", type=int, default=20000, help="حجم عيّنة الإثبات")
    r.add_argument("--active", action="store_true",
                   help="تفعيل فحوص المصادقة/سحب البيانات (POST + حمولات كشف غير مدمّرة)")
    r.set_defaults(func=cmd_run)

    v = sub.add_parser("verify", help="التحقق من ملكية الأهداف فقط")
    v.add_argument("--scope", required=True)
    v.set_defaults(func=cmd_verify)

    args = p.parse_args(argv)
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
