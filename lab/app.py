#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
========================================================================
 Megganew Security Training Lab  —  بيئة تدريب اختبار الاختراق (محلية)
========================================================================

تطبيق ويب مليء بثغرات حقيقية *عمداً* — صُمّم للتعلّم العملي فقط.

  !!!  تحذير أمني مهم  !!!
  - هذا التطبيق هشّ عمداً ويحتوي ثغرات قابلة للاستغلال فعلاً.
  - شغّله على جهازك محلياً فقط (127.0.0.1).
  - لا ترفعه على أي سيرفر عام، ولا تعرّضه للإنترنت، ولا تضعه خلف دومين.
  - الهدف: تتدرّب على كل ثغرة بيدك في بيئة تملكها 100%.
  - المهارات اللي تتعلمها هنا، تطبّقها لاحقاً فقط على أنظمة لديك تفويض
    مكتوب وموثّق لفحصها.

التشغيل:
    cd lab
    pip install -r ../requirements.txt
    python app.py
ثم افتح:  http://127.0.0.1:5000

كل ثغرة في الكود معلّمة بوسم:   # [VULN-XX] <الاسم>
وكل ثغرة لها شرح وخطوات استغلال وإصلاح في مجلد docs/.
"""

import os
import sqlite3
import hashlib
import subprocess
import urllib.request
from flask import (
    Flask, request, g, redirect, make_response,
    render_template_string, send_file, Response
)

APP_DIR   = os.path.dirname(os.path.abspath(__file__))
DB_PATH   = os.path.join(APP_DIR, "lab.db")
FILES_DIR = os.path.join(APP_DIR, "files")
UPLOAD_DIR = os.path.join(APP_DIR, "uploads")

app = Flask(__name__)

# [VULN-09] Sensitive Data Exposure / Hardcoded Secret
# سر مكتوب داخل الكود (anti-pattern) — يُستخرج عبر /debug أو كشف المصدر.
APP_SECRET = "sup3r-s3cret-flag{megganew_training_lab}"
app.config["SECRET_KEY"] = "insecure-static-key-123"   # مفتاح ثابت ضعيف


# ----------------------------------------------------------------------
# قاعدة البيانات (SQLite) + بيانات تجريبية
# ----------------------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    db = sqlite3.connect(DB_PATH)
    db.executescript(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password_md5 TEXT,
            role TEXT,
            api_key TEXT,
            credit_card TEXT,
            private_note TEXT
        );
        CREATE TABLE messages (
            id INTEGER PRIMARY KEY,
            author TEXT,
            body TEXT
        );
        """
    )
    # md5 لكلمات السر = تخزين ضعيف عمداً  # [VULN-05]
    def md5(s): return hashlib.md5(s.encode()).hexdigest()
    users = [
        (1, "admin",  md5("admin123"),  "admin", "AK-ADMIN-9f8e7d", "4111-1111-1111-1111", "خطة الشركة السرية"),
        (2, "ahmed",  md5("password"),  "user",  "AK-USER-aaa111",  "5555-4444-3333-2222", "ملاحظة خاصة لأحمد"),
        (3, "sara",   md5("qwerty"),    "user",  "AK-USER-bbb222",  "6011-0009-9013-9424", "رقم هاتفي الخاص"),
        (4, "ceo",    md5("Darbuna@2026"), "admin", "AK-CEO-topsecret", "3782-822463-10005", "راتب الموظفين وبيانات مالية"),
    ]
    db.executemany("INSERT INTO users VALUES (?,?,?,?,?,?,?)", users)
    db.executemany(
        "INSERT INTO messages (author, body) VALUES (?,?)",
        [("admin", "أهلاً بالجميع في لوحة الرسائل"),
         ("sara",  "تجربة رسالة عادية")],
    )
    db.commit()
    db.close()
    # ملف تجريبي لقسم Path Traversal
    os.makedirs(FILES_DIR, exist_ok=True)
    with open(os.path.join(FILES_DIR, "welcome.txt"), "w", encoding="utf-8") as f:
        f.write("هذا ملف عام يمكن تنزيله بأمان.\n")
    os.makedirs(UPLOAD_DIR, exist_ok=True)


# ----------------------------------------------------------------------
# قالب الصفحة (inline) — بسيط عمداً
# ----------------------------------------------------------------------
PAGE = """
<!doctype html><html lang="ar" dir="rtl"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Megganew Lab</title>
<style>
 body{font-family:system-ui,Arial;max-width:900px;margin:24px auto;padding:0 16px;background:#0f1115;color:#e6e6e6}
 a{color:#6ea8fe} h1,h2{color:#fff} code,pre{background:#1b1f27;padding:2px 6px;border-radius:6px}
 .card{background:#161a22;border:1px solid #232a36;border-radius:12px;padding:16px;margin:14px 0}
 input,button,textarea{padding:8px;border-radius:8px;border:1px solid #333;background:#11141a;color:#eee}
 .v{color:#ff7b7b;font-weight:bold} .nav a{margin-left:12px}
</style></head><body>
<div class="nav">
 <a href="/">الرئيسية</a><a href="/login">دخول</a><a href="/profile?id=1">بروفايل</a>
 <a href="/search?q=a">بحث</a><a href="/messages">رسائل</a><a href="/tools">أدوات</a>
 <a href="/admin">لوحة الأدمن</a>
</div><hr>
{{ body|safe }}
</body></html>
"""

def page(body_html):
    return render_template_string(PAGE, body=body_html)


# ----------------------------------------------------------------------
# الصفحة الرئيسية
# ----------------------------------------------------------------------
@app.route("/")
def index():
    who = request.cookies.get("session", "زائر")
    body = f"""
    <h1>🧪 Megganew Security Training Lab</h1>
    <p>أنت مسجّل كـ: <code>{who}</code></p>
    <div class="card">
      <b>بيئة تدريب محلية</b> — كل رابط هنا فيه ثغرة واحدة أو أكثر لتتمرّن عليها.
      راجع <code>docs/</code> لكل ثغرة: الشرح + الاستغلال + الإصلاح.
    </div>
    <div class="card">
      <h2>قائمة التمارين</h2>
      <ul>
        <li><a href="/login">تسجيل الدخول</a> — <span class="v">SQL Injection</span> + <span class="v">Broken Auth</span></li>
        <li><a href="/search?q=test">البحث</a> — <span class="v">SQLi (UNION)</span> + <span class="v">Reflected XSS</span></li>
        <li><a href="/messages">الرسائل</a> — <span class="v">Stored XSS</span> + <span class="v">CSRF</span></li>
        <li><a href="/profile?id=1">البروفايل</a> — <span class="v">IDOR / Broken Access Control</span></li>
        <li><a href="/admin">لوحة الأدمن</a> — <span class="v">Missing Access Control</span></li>
        <li><a href="/staff">لوحة الموظفين</a> — <span class="v">Privilege Escalation (Trusted Header / Cookie Forgery)</span></li>
        <li><a href="/tools">الأدوات</a> — <span class="v">SSRF</span> + <span class="v">Command Injection</span></li>
        <li><a href="/download?file=welcome.txt">تنزيل ملف</a> — <span class="v">Path Traversal</span></li>
        <li><a href="/greet?name=Ahmed">ترحيب</a> — <span class="v">SSTI</span></li>
        <li><a href="/upload">رفع ملف</a> — <span class="v">Insecure File Upload</span></li>
        <li><a href="/debug">debug</a> — <span class="v">Sensitive Data Exposure</span></li>
      </ul>
    </div>
    """
    return page(body)


# ----------------------------------------------------------------------
# [VULN-01] SQL Injection  +  [VULN-05] Broken Authentication
# ----------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    msg = ""
    if request.method == "POST":
        u = request.form.get("username", "")
        p = request.form.get("password", "")
        pm = hashlib.md5(p.encode()).hexdigest()
        # [VULN-01] استعلام مبني بدمج نصي مباشر — حقن SQL
        q = ("SELECT * FROM users WHERE username = '%s' "
             "AND password_md5 = '%s'" % (u, pm))
        try:
            row = get_db().execute(q).fetchone()
        except Exception as e:
            # [VULN-09] رسالة خطأ مفصّلة تكشف الاستعلام
            return page(f"<h2>خطأ SQL</h2><pre>{e}</pre><pre>{q}</pre>")
        if row:
            resp = make_response(page(
                f"<h2>أهلاً {row['username']}</h2>"
                f"<p>دورك: <code>{row['role']}</code></p>"
                f"<p><a href='/profile?id={row['id']}'>بروفايلك</a></p>"))
            # [VULN-05] كوكي جلسة = اسم المستخدم بنص صريح بدون توقيع → قابل للتزوير
            resp.set_cookie("session", row["username"])
            resp.set_cookie("role", row["role"])
            return resp
        msg = "<p class='v'>بيانات خاطئة</p>"
    form = f"""
    <h1>تسجيل الدخول</h1>{msg}
    <form method="post"><div class="card">
      <p>المستخدم: <input name="username"></p>
      <p>السر: <input name="password" type="password"></p>
      <button>دخول</button>
    </div></form>
    <p>جرّب: <code>admin</code> / <code>admin123</code> — أو تجاوز الدخول بحقن SQL.</p>
    """
    return page(form)


# ----------------------------------------------------------------------
# [VULN-02] SQL Injection (UNION)  +  [VULN-03] Reflected XSS
# ----------------------------------------------------------------------
@app.route("/search")
def search():
    q = request.args.get("q", "")
    # [VULN-02] دمج نصي في الاستعلام → حقن SQL (UNION-based)
    sql = "SELECT id, username, role FROM users WHERE username LIKE '%%%s%%'" % q
    rows, err = [], ""
    try:
        rows = get_db().execute(sql).fetchall()
    except Exception as e:
        err = f"<pre class='v'>{e}</pre>"
    out = "".join(f"<li>#{r['id']} — {r['username']} ({r['role']})</li>" for r in rows)
    # [VULN-03] عكس مدخل المستخدم في HTML بدون ترميز → XSS منعكس
    body = f"""
    <h1>بحث المستخدمين</h1>
    <form><input name="q" value="{q}"><button>بحث</button></form>
    <p>نتائج البحث عن: {q}</p>
    {err}<ul>{out}</ul>
    """
    return page(body)


# ----------------------------------------------------------------------
# [VULN-04] Stored XSS  +  [VULN-08] CSRF
# ----------------------------------------------------------------------
@app.route("/messages", methods=["GET", "POST"])
def messages():
    db = get_db()
    if request.method == "POST":
        # [VULN-08] لا يوجد CSRF token — أي موقع يقدر يرسل هالطلب
        author = request.cookies.get("session", "anon")
        body = request.form.get("body", "")
        db.execute("INSERT INTO messages (author, body) VALUES (?,?)", (author, body))
        db.commit()
        return redirect("/messages")
    rows = db.execute("SELECT author, body FROM messages ORDER BY id DESC").fetchall()
    # [VULN-04] عرض محتوى مخزّن بدون ترميز → XSS مخزّن
    items = "".join(f"<div class='card'><b>{r['author']}:</b> {r['body']}</div>" for r in rows)
    body = f"""
    <h1>لوحة الرسائل</h1>
    <form method="post"><div class="card">
      <textarea name="body" placeholder="اكتب رسالة..."></textarea><br>
      <button>إرسال</button></div></form>
    {items}
    """
    return page(body)


# ----------------------------------------------------------------------
# [VULN-06] IDOR / Broken Access Control
# ----------------------------------------------------------------------
@app.route("/profile")
def profile():
    uid = request.args.get("id", "1")
    # [VULN-06] يعرض بيانات أي مستخدم حسب id بدون التحقق من هوية الطالب
    row = get_db().execute(
        "SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    if not row:
        return page("<p>مستخدم غير موجود</p>")
    body = f"""
    <h1>بروفايل #{row['id']}</h1>
    <div class="card">
      <p>المستخدم: <b>{row['username']}</b></p>
      <p>الدور: {row['role']}</p>
      <p class="v">مفتاح API: {row['api_key']}</p>
      <p class="v">بطاقة ائتمان: {row['credit_card']}</p>
      <p class="v">ملاحظة خاصة: {row['private_note']}</p>
    </div>
    <p>جرّب تغيّر <code>?id=</code> لرؤية بيانات مستخدمين آخرين.</p>
    """
    return page(body)


# ----------------------------------------------------------------------
# [VULN-07] Missing Function-Level Access Control
# ----------------------------------------------------------------------
@app.route("/admin")
def admin():
    # [VULN-07] صفحة إدارية حساسة بدون أي تحقق من الصلاحية
    rows = get_db().execute("SELECT id, username, role, api_key, credit_card FROM users").fetchall()
    tbl = "".join(
        f"<tr><td>{r['id']}</td><td>{r['username']}</td><td>{r['role']}</td>"
        f"<td>{r['api_key']}</td><td>{r['credit_card']}</td></tr>" for r in rows)
    body = f"""
    <h1>🔐 لوحة الأدمن</h1>
    <p class="v">هاي الصفحة لازم تكون للأدمن فقط — بس ماكو أي تحقق!</p>
    <table border=1 cellpadding=6>
      <tr><th>id</th><th>user</th><th>role</th><th>api_key</th><th>card</th></tr>
      {tbl}
    </table>
    """
    return page(body)


# ----------------------------------------------------------------------
# [VULN-15] Privilege Escalation via Trusted Header / Forged Cookie
# ----------------------------------------------------------------------
@app.route("/staff")
def staff():
    # [VULN-15a] يثق برأس X-Forwarded-For كأنه دليل "طلب من الشبكة الداخلية"
    xff = request.headers.get("X-Forwarded-For", "")
    # [VULN-15b] يثق بكوكي role بدون أي توقيع أو تحقق من جلسة حقيقية
    role_cookie = request.cookies.get("role", "")
    is_staff = xff.strip() in ("127.0.0.1", "localhost") or role_cookie == "admin"
    if not is_staff:
        resp = make_response(page("<h1>403</h1><p class='v'>ممنوع — موظفون فقط.</p>"))
        resp.status_code = 403
        return resp
    rows = get_db().execute(
        "SELECT username, private_note, credit_card FROM users").fetchall()
    tbl = "".join(f"<li>{r['username']}: {r['private_note']} — {r['credit_card']}</li>"
                  for r in rows)
    body = f"""
    <h1>🧑‍💼 لوحة الموظفين (Staff Panel)</h1>
    <p class="v">يُفترض أنها للموظفين من الشبكة الداخلية فقط!</p>
    <ul>{tbl}</ul>
    """
    return page(body)


# ----------------------------------------------------------------------
# أدوات: [VULN-10] SSRF  +  [VULN-11] Command Injection
# ----------------------------------------------------------------------
@app.route("/tools")
def tools():
    body = """
    <h1>أدوات النظام</h1>
    <div class="card"><h2>جلب رابط (URL Fetcher)</h2>
      <form action="/fetch"><input name="url" value="http://127.0.0.1:5000/" size=40><button>جلب</button></form>
      <small>ثغرة SSRF</small></div>
    <div class="card"><h2>فحص اتصال (Ping)</h2>
      <form action="/ping"><input name="host" value="127.0.0.1"><button>ping</button></form>
      <small>ثغرة Command Injection</small></div>
    """
    return page(body)


@app.route("/fetch")
def fetch():
    url = request.args.get("url", "")
    # [VULN-10] يجلب أي URL يعطيه المستخدم → SSRF (وصول لخدمات داخلية/ميتاداتا)
    try:
        data = urllib.request.urlopen(url, timeout=5).read()[:4000]
        content = data.decode("utf-8", "replace")
    except Exception as e:
        content = f"خطأ: {e}"
    return page(f"<h1>نتيجة الجلب</h1><pre>{content}</pre>")


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # [VULN-11] دمج مدخل المستخدم في أمر شل → حقن أوامر
    cmd = "ping -c 2 " + host
    try:
        out = subprocess.getoutput(cmd)
    except Exception as e:
        out = str(e)
    return page(f"<h1>ping</h1><pre>$ {cmd}\n\n{out}</pre>")


# ----------------------------------------------------------------------
# [VULN-12] Path Traversal
# ----------------------------------------------------------------------
@app.route("/download")
def download():
    fname = request.args.get("file", "welcome.txt")
    # [VULN-12] دمج اسم الملف مباشرة بدون تطهير → اجتياز مسار
    path = os.path.join(FILES_DIR, fname)
    try:
        return send_file(path)
    except Exception as e:
        return page(f"<pre class='v'>{e}</pre><p>path: {path}</p>")


# ----------------------------------------------------------------------
# [VULN-13] SSTI (Server-Side Template Injection)
# ----------------------------------------------------------------------
@app.route("/greet")
def greet():
    name = request.args.get("name", "Guest")
    # [VULN-13] تمرير مدخل المستخدم داخل قالب يُنفّذ → حقن قالب من جهة الخادم
    tpl = "<h1>أهلاً " + name + "!</h1><p>شلونك اليوم؟</p>"
    return page(render_template_string(tpl))


# ----------------------------------------------------------------------
# [VULN-14] Insecure File Upload
# ----------------------------------------------------------------------
@app.route("/upload", methods=["GET", "POST"])
def upload():
    msg = ""
    if request.method == "POST":
        f = request.files.get("file")
        if f:
            # [VULN-14] يحفظ أي ملف بأي امتداد بدون فحص نوع/محتوى
            dest = os.path.join(UPLOAD_DIR, f.filename)
            f.save(dest)
            msg = f"<p>تم الرفع: <code>{dest}</code></p>"
    body = f"""
    <h1>رفع ملف</h1>{msg}
    <form method="post" enctype="multipart/form-data"><div class="card">
      <input type="file" name="file"><button>رفع</button></div></form>
    <small>بدون فحص الامتداد أو نوع المحتوى.</small>
    """
    return page(body)


# ----------------------------------------------------------------------
# [VULN-09] Sensitive Data Exposure
# ----------------------------------------------------------------------
@app.route("/debug")
def debug():
    # [VULN-09] نقطة نهاية تكشف أسرار وإعدادات حساسة
    info = {
        "APP_SECRET": APP_SECRET,
        "SECRET_KEY": app.config["SECRET_KEY"],
        "DB_PATH": DB_PATH,
        "cwd": os.getcwd(),
        "env_sample": {k: os.environ.get(k) for k in ("HOME", "USER", "PATH")},
    }
    rows = "".join(f"<tr><td>{k}</td><td><code>{v}</code></td></tr>" for k, v in info.items())
    return page(f"<h1>Debug</h1><table border=1 cellpadding=6>{rows}</table>")


if __name__ == "__main__":
    init_db()
    print("=" * 60)
    print(" Megganew Training Lab يعمل على  http://127.0.0.1:5000")
    print(" بيئة تدريب محلية — لا ترفعها على الإنترنت")
    print("=" * 60)
    # يستمع محلياً فقط
    app.run(host="127.0.0.1", port=5000, debug=False)
