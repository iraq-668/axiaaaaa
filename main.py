from datetime import datetime
import os
import sqlite3
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
import requests

app = FastAPI(
    title="Axia Enterprise SOC & Cyber Defense Suite",
    version="12.0.0",
    docs_url=None,
    redoc_url=None
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

TELEGRAM_BOT_TOKEN = "8315783570:AAEGdX1a82fHhjFTjTWb1N0fTJnb2s5cDdA"
TELEGRAM_CHAT_ID = "936441187"
DATABASE_FILENAME = "axia_enterprise_core.db"

def initialize_enterprise_database():
    connection = sqlite3.connect(DATABASE_FILENAME)
    cursor = connection.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS waf_security_logs (
            log_id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT, source_ip TEXT, http_method TEXT, request_uri TEXT,
            response_status TEXT, threat_severity TEXT, attack_signature TEXT,
            user_agent_string TEXT, raw_payload TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS global_ip_blacklist (
            ip_address TEXT PRIMARY KEY, block_reason TEXT, threat_level TEXT,
            banned_timestamp TEXT, violation_count INTEGER DEFAULT 1
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS portal_visitor_analytics (
            visitor_id INTEGER PRIMARY KEY AUTOINCREMENT,
            visit_time TEXT, visitor_ip TEXT, requested_path TEXT,
            client_browser TEXT, user_session_token TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS soc_operators_staff (
            operator_id INTEGER PRIMARY KEY AUTOINCREMENT,
            operator_name TEXT, operator_email TEXT, security_role TEXT,
            account_state TEXT, joined_date TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS system_core_settings (
            config_id INTEGER PRIMARY KEY AUTOINCREMENT,
            master_username TEXT, master_password_secret TEXT,
            defense_mode TEXT, last_configuration_update TEXT
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS client_inquiry_tickets (
            ticket_code INTEGER PRIMARY KEY AUTOINCREMENT,
            client_name TEXT, client_email TEXT, subject_title TEXT,
            message_body TEXT, ticket_status TEXT, submission_timestamp TEXT
        )
    """)
    cursor.execute("SELECT COUNT(*) FROM system_core_settings")
    if cursor.fetchone()[0] == 0:
        cursor.execute(
            "INSERT INTO system_core_settings (master_username, master_password_secret, defense_mode, last_configuration_update) VALUES (?, ?, ?, ?)",
            ("admin", "axia2026secure", "DEFCON_1_ACTIVE", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        )
    connection.commit()
    connection.close()

initialize_enterprise_database()

def send_telegram_security_alert(alert_message: str, target_ip_to_manage: str = None):
    try:
        api_url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        keyboard_layout = {
            "inline_keyboard": [
                [
                    {"text": "🚫 حظر الـ IP فوراً", "callback_data": f"cmd_block_{target_ip_to_manage}"},
                    {"text": "📊 تقرير السستم", "callback_data": "cmd_status"}
                ],
                [
                    {"text": "🧹 تطهير السجلات", "callback_data": "cmd_purge"},
                    {"text": "🛡️ رفع الحظر عن الـ IP", "callback_data": f"cmd_unblock_{target_ip_to_manage}"}
                ]
            ]
        } if target_ip_to_manage else {
            "inline_keyboard": [
                [{"text": "📊 تقرير السستم", "callback_data": "cmd_status"}]
            ]
        }
        payload_data = {
            "chat_id": TELEGRAM_CHAT_ID,
            "text": alert_message,
            "parse_mode": "Markdown",
            "reply_markup": keyboard_layout
        }
        requests.post(api_url, json=payload_data, timeout=5)
    except Exception as network_error:
        print(f"[Telegram Alert Exception]: {network_error}")

def evaluate_waf_security_rules(client_ip: str, http_method: str, request_path: str, query_string: str, user_agent: str):
    combined_payload = f"{request_path}?{query_string}".lower()
    current_time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    xss_vectors = ["<script>", "javascript:", "onerror", "onload", "eval(", "document.cookie", "alert("]
    sqli_vectors = ["union select", "or 1=1", "drop table", "exec(", "information_schema", "select * from", "--", "/*!"]
    rce_vectors = ["cat /etc/passwd", "ping -c", "nc -e", "bash -i", "cmd.exe", "powershell"]
    
    triggered_attack = None
    severity_rating = "LOW"
    
    for vector in xss_vectors:
        if vector in combined_payload:
            triggered_attack = f"Cross-Site Scripting (XSS) -> [{vector}]"
            severity_rating = "CRITICAL"
            break
            
    if not triggered_attack:
        for vector in sqli_vectors:
            if vector in combined_payload:
                triggered_attack = f"SQL Injection (SQLi) -> [{vector}]"
                severity_rating = "HIGH"
                break
                
    if not triggered_attack:
        for vector in rce_vectors:
            if vector in combined_payload:
                triggered_attack = f"Remote Code Execution -> [{vector}]"
                severity_rating = "EMERGENCY"
                break

    db_conn = sqlite3.connect(DATABASE_FILENAME)
    db_cursor = db_conn.cursor()
    
    if triggered_attack:
        db_cursor.execute(
            "INSERT INTO waf_security_logs (timestamp, source_ip, http_method, request_uri, response_status, threat_severity, attack_signature, user_agent_string, raw_payload) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (current_time_str, client_ip, http_method, request_path, "403", severity_rating, triggered_attack, user_agent, combined_payload)
        )
        db_cursor.execute("""
            INSERT INTO global_ip_blacklist (ip_address, block_reason, threat_level, banned_timestamp, violation_count)
            VALUES (?, ?, ?, ?, 1)
            ON CONFLICT(ip_address) DO UPDATE SET violation_count = violation_count + 1, banned_timestamp = ?
        """, (client_ip, triggered_attack, severity_rating, current_time_str, current_time_str))
        db_conn.commit()
        db_conn.close()
        
        send_telegram_security_alert(
            f"🚨 *[Axia WAF] رصد محاولة اختراق نشطة!* 🚨\n\n"
            f"🛡️ نوع الهجوم: `{triggered_attack}`\n"
            f"⚡ الخطورة: `{severity_rating}`\n"
            f"🌐 مصدر الآي بي: `{client_ip}`\n"
            f"📂 المسار المستهدف: `{request_path}`\n"
            f"🕒 التوقيت: `{current_time_str}`",
            client_ip
        )
        return True, triggered_attack
    else:
        db_cursor.execute(
            "INSERT INTO waf_security_logs (timestamp, source_ip, http_method, request_uri, response_status, threat_severity, attack_signature, user_agent_string, raw_payload) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (current_time_str, client_ip, http_method, request_path, "200", "SAFE", "None", user_agent, combined_payload)
        )
        db_conn.commit()
        db_conn.close()
        return False, None

def check_if_ip_is_banned(ip_to_check: str) -> bool:
    db_conn = sqlite3.connect(DATABASE_FILENAME)
    db_cursor = db_conn.cursor()
    db_cursor.execute("SELECT ip_address FROM global_ip_blacklist WHERE ip_address = ?", (ip_to_check,))
    result = db_cursor.fetchone()
    db_conn.close()
    return result is not None

@app.middleware("http")
async def enterprise_waf_middleware(request: Request, call_next):
    client_ip = request.client.host if request.client else "127.0.0.1"
    request_path = request.url.path
    query_string = str(request.url.query)
    http_method = request.method
    user_agent = request.headers.get("user-agent", "Unknown")
    
    exempt_paths = ["/soc-dashboard", "/login", "/logout", "/telegram-webhook", "/contact-submit"]
    if any(request_path.startswith(p) for p in exempt_paths):
        return await call_next(request)
        
    if check_if_ip_is_banned(client_ip):
        return HTMLResponse(content=f"""
        <!DOCTYPE html><html lang="ar" dir="rtl"><head><meta charset="UTF-8"><title>محظور</title>
        <style>body{{background:#030712;color:#f87171;font-family:Tahoma;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}}
        .box{{background:#0f172a;border:2px solid #ef4444;padding:45px;border-radius:18px;text-align:center;max-width:500px}}</style></head>
        <body><div class="box"><h1>🚫 تم حظر عنوان الـ IP الخاص بك</h1><p>تم تعليق صلاحية الوصول تلقائياً نظراً لرصد أنشطة مشبوهة.</p><div style="margin-top:15px;color:#38bdf8;">IP: {client_ip}</div></div></body></html>
        """, status_code=403)
        
    if http_method == "GET" and not request_path.endswith(".ico"):
        try:
            db_conn = sqlite3.connect(DATABASE_FILENAME)
            db_cursor = db_conn.cursor()
            db_cursor.execute("INSERT INTO portal_visitor_analytics (visit_time, visitor_ip, requested_path, client_browser, user_session_token) VALUES (?, ?, ?, ?, ?)",
                           (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), client_ip, request_path, user_agent, request.cookies.get("session", "guest")))
            db_conn.commit()
            db_conn.close()
        except Exception:
            pass

    is_attack_detected, attack_name = evaluate_waf_security_rules(client_ip, http_method, request_path, query_string, user_agent)
    if is_attack_detected:
        return HTMLResponse(content=f"""
        <!DOCTYPE html><html lang="ar" dir="rtl"><head><meta charset="UTF-8"><title>Axia WAF</title>
        <style>body{{background:#030712;color:#fff;font-family:Tahoma;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}}
        .card{{background:#0f172a;border:2px solid #ef4444;padding:45px;border-radius:18px;text-align:center;width:480px}}</style></head>
        <body><div class="card"><h2 style="color:#ef4444">🛡️ تم التصدي للهجمة بنجاح!</h2><p>تم رصد توقيع مشبوه (<b>{attack_name}</b>) وحظر الطلب.</p><a href="/" style="display:inline-block;background:#3b82f6;color:white;padding:10px 20px;text-decoration:none;border-radius:8px;margin-top:20px;">الرئيسية</a></div></body></html>
        """, status_code=403)

    return await call_next(request)

@app.get("/", response_class=HTMLResponse)
async def enterprise_homepage():
    return """
    <!DOCTYPE html>
    <html lang="ar" dir="rtl">
    <head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Axia Enterprise | الحلول الأمنية المتقدمة</title>
    <script src="https://cdn.jsdelivr.net/npm/@tailwindcss/browser@4"></script>
    <style>body { background: #030712; color: #f8fafc; font-family: Tahoma; }</style>
    </head>
    <body class="min-h-screen flex flex-col justify-between">
        <header class="border-b border-slate-800 bg-[#0f172a]/90 backdrop-blur sticky top-0 z-50">
            <div class="max-w-7xl mx-auto px-6 py-4 flex justify-between items-center">
                <div class="flex items-center gap-3"><span class="text-3xl">🛡️</span><h1 class="text-lg font-black text-blue-400">AXIA ENTERPRISE</h1></div>
                <a href="/login" class="bg-blue-600 hover:bg-blue-500 text-white px-5 py-2.5 rounded-xl text-xs font-bold transition">لوحة تحكم الـ SOC</a>
            </div>
        </header>
        <main class="max-w-7xl mx-auto px-6 py-24 text-center">
            <h2 class="text-5xl font-black mb-6">أمان سيبراني متكامل <br><span class="text-blue-500">لبنيتك التحتية وتطبيقاتك</span></h2>
            <p class="text-slate-400 text-lg max-w-2xl mx-auto mb-10">نظام حماية متطور يحمي سيرفراتك ويرصد الزوار بدقة عالية.</p>
            <a href="/login" class="bg-blue-600 hover:bg-blue-500 text-white font-bold px-8 py-4 rounded-2xl shadow-xl transition">الدخول لوحة العمليات</a>
        </main>
        <footer class="border-t border-slate-800 text-center py-6 text-xs text-slate-500">جميع الحقوق محفوظة © 2026 Axia Enterprise</footer>
    </body>
    </html>
    """

@app.post("/login")
async def login_form_submit(username: str = Form(...), password: str = Form(...)):
    db_conn = sqlite3.connect(DATABASE_FILENAME)
    db_cursor = db_conn.cursor()
    db_cursor.execute("SELECT master_username, master_password_secret FROM system_core_settings WHERE config_id = 1")
    config_record = db_cursor.fetchone()
    db_conn.close()
    if config_record and username == config_record[0] and password == config_record[1]:
        response_redirect = RedirectResponse(url="/soc-dashboard", status_code=303)
        response_redirect.set_cookie(key="session", value="authenticated_admin_token", httponly=True)
        return response_redirect
    return HTMLResponse(content="<script>alert('خطأ في اسم المستخدم أو كلمة المرور!'); window.location.href='/login';</script>")

@app.get("/login", response_class=HTMLResponse)
async def login_portal_page():
    return """
    <!DOCTYPE html><html lang="ar" dir="rtl"><head><meta charset="UTF-8"><title>تسجيل الدخول</title>
    <script src="https://cdn.jsdelivr.net/npm/@tailwindcss/browser@4"></script>
    <style>body { background: #030712; color: #f8fafc; font-family: Tahoma; }</style></head>
    <body class="h-screen flex justify-center items-center">
        <div class="bg-[#0f172a] border border-slate-800 p-8 rounded-3xl w-96 shadow-2xl">
            <h2 class="text-xl font-bold text-blue-400 mb-6 text-center">تسجيل دخول المشرف</h2>
            <form action="/login" method="post" class="space-y-4">
                <input type="text" name="username" placeholder="اسم المستخدم" required class="w-full bg-[#030712] border border-slate-800 rounded-xl px-4 py-3 text-sm text-white">
                <input type="password" name="password" placeholder="كلمة المرور" required class="w-full bg-[#030712] border border-slate-800 rounded-xl px-4 py-3 text-sm text-white">
                <button type="submit" class="w-full bg-blue-600 text-white font-bold py-3 rounded-xl">دخول</button>
            </form>
        </div>
    </body></html>
    """

@app.get("/logout")
async def logout_action():
    response_redirect = RedirectResponse(url="/login", status_code=303)
    response_redirect.delete_cookie(key="session")
    return response_redirect

@app.get("/soc-dashboard", response_class=HTMLResponse)
async def soc_dashboard_central_view(request: Request):
    if request.cookies.get("session") != "authenticated_admin_token":
        return RedirectResponse(url="/login")
        
    db_conn = sqlite3.connect(DATABASE_FILENAME)
    db_cursor = db_conn.cursor()
    db_cursor.execute("SELECT timestamp, source_ip, http_method, request_uri, response_status, threat_severity, attack_signature FROM waf_security_logs ORDER BY log_id DESC LIMIT 45")
    security_logs_data = db_cursor.fetchall()
    db_cursor.execute("SELECT visit_time, visitor_ip, requested_path, client_browser FROM portal_visitor_analytics ORDER BY visitor_id DESC LIMIT 30")
    visitor_logs_data = db_cursor.fetchall()
    db_cursor.execute("SELECT ip_address, block_reason, threat_level, banned_timestamp, violation_count FROM global_ip_blacklist ORDER BY banned_timestamp DESC")
    blacklist_data = db_cursor.fetchall()
    db_cursor.execute("SELECT operator_id, operator_name, operator_email, security_role, account_state FROM soc_operators_staff ORDER BY operator_id DESC")
    staff_data = db_cursor.fetchall()
    db_cursor.execute("SELECT master_username FROM system_core_settings WHERE config_id = 1")
    current_admin_name = db_cursor.fetchone()[0]
    db_cursor.execute("SELECT COUNT(*) FROM waf_security_logs WHERE response_status = '403'")
    total_blocked_attacks = db_cursor.fetchone()[0]
    db_cursor.execute("SELECT COUNT(*) FROM waf_security_logs")
    total_inspected_requests = db_cursor.fetchone()[0]
    db_cursor.execute("SELECT COUNT(*) FROM global_ip_blacklist")
    total_banned_ips = db_cursor.fetchone()[0]
    db_cursor.execute("SELECT COUNT(*) FROM portal_visitor_analytics")
    total_visitors_count = db_cursor.fetchone()[0]
    db_conn.close()

    logs_table_html = "".join([f"<tr class='border-b border-slate-800/60'><td class='py-3 px-4 text-xs font-mono'>{item[0]}</td><td class='py-3 px-4'><span class='px-2.5 py-1 rounded-full text-xs font-bold {('bg-emerald-950 text-emerald-400' if item[4]=='200' else 'bg-rose-950 text-rose-400')}'>{item[4]} ({item[5]})</span></td><td class='py-3 px-4 text-xs font-mono dir-ltr text-right'>{item[3]}</td><td class='py-3 px-4 text-xs font-bold text-slate-300'>{item[6]}</td><td class='py-3 px-4 text-xs font-mono dir-ltr'>{item[1]}</td></tr>" for item in security_logs_data])
    visitors_table_html = "".join([f"<tr class='border-b border-slate-800/60'><td class='py-3 px-4 text-xs'>{v[0]}</td><td class='py-3 px-4 text-xs font-mono dir-ltr text-right'>{v[2]}</td><td class='py-3 px-4 text-xs font-mono dir-ltr'>{v[1]}</td></tr>" for v in visitor_logs_data])
    blacklist_table_html = "".join([f"<tr class='border-b border-slate-800/60'><td class='py-3 px-4 text-xs font-mono dir-ltr'>{b[0]}</td><td class='py-3 px-4 text-xs text-slate-300'>{b[1]}</td><td class='py-3 px-4 text-xs'><span class='bg-rose-950 text-rose-400 px-2 py-0.5 rounded font-bold'>{b[2]}</span></td><td class='py-3 px-4 text-xs text-slate-400'>{b[3]} ({b[4]} مرات)</td><td class='py-3 px-4 text-xs'><a href='/admin/unblock-ip/{b[0]}' class='text-emerald-400 font-bold hover:underline'>رفع الحظر</a></td></tr>" for b in blacklist_data])
    staff_table_html = "".join([f"<tr class='border-b border-slate-800/60'><td class='py-3 px-4 text-sm font-bold text-white'>{s[1]}</td><td class='py-3 px-4 text-xs text-slate-400'>{s[2]}</td><td class='py-3 px-4 text-xs'><span class='bg-blue-950 text-blue-400 px-2.5 py-1 rounded-full'>{s[3]}</span></td><td class='py-3 px-4 text-xs'><a href='/admin/remove-staff/{s[0]}' class='text-rose-400 font-bold hover:underline'>حذف</a></td></tr>" for s in staff_data])

    return HTMLResponse(content=f"""
    <!DOCTYPE html><html lang="ar" dir="rtl"><head><meta charset="UTF-8"><title>Axia SOC Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/@tailwindcss/browser@4"></script>
    <meta http-equiv="refresh" content="12">
    <style>body {{ background: #030712; color: #f8fafc; font-family: Tahoma; }} .dir-ltr {{ direction: ltr; }}</style>
    <script>
        function switchDashboardTab(tabId) {{
            document.querySelectorAll('.dashboard-tab').forEach(el => el.classList.add('hidden'));
            document.querySelectorAll('.tab-menu-btn').forEach(el => el.classList.remove('bg-blue-600', 'text-white'));
            document.querySelectorAll('.tab-menu-btn').forEach(el => el.classList.add('text-slate-400', 'hover:bg-slate-800'));
            document.getElementById(tabId).classList.remove('hidden');
            event.currentTarget.classList.add('bg-blue-600', 'text-white');
            event.currentTarget.classList.remove('text-slate-400', 'hover:bg-slate-800');
        }}
    </script></head>
    <body class="min-h-screen flex flex-col">
        <header class="bg-[#0f172a] border-b border-slate-800 px-8 py-4 flex justify-between items-center sticky top-0 z-50">
            <div class="flex items-center gap-3"><span class="text-2xl">🛡️</span><div><h1 class="text-base font-black text-blue-400">Axia Enterprise SOC</h1><span class="text-xs text-slate-400">المشرف: <b class="text-white">{current_admin_name}</b></span></div></div>
            <div class="flex gap-4"><a href="/" target="_blank" class="bg-slate-800 text-slate-200 px-4 py-2 rounded-xl text-xs font-bold">الموقع 🌐</a><a href="/admin/purge-all-logs" class="bg-rose-950 text-rose-400 px-4 py-2 rounded-xl text-xs font-bold">تصفير السجلات</a><a href="/logout" class="bg-slate-800 text-slate-300 px-4 py-2 rounded-xl text-xs font-bold">خروج</a></div>
        </header>
        <div class="max-w-7xl w-full mx-auto px-6 mt-8 grid grid-cols-1 md:grid-cols-4 gap-6">
            <div class="bg-[#0f172a] border border-slate-800 p-6 rounded-2xl"><div class="text-xs text-slate-400 mb-2">إجمالي الزيارات</div><div class="text-3xl font-black text-blue-400">{total_visitors_count}</div></div>
            <div class="bg-[#0f172a] border border-slate-800 p-6 rounded-2xl"><div class="text-xs text-slate-400 mb-2">الـ IPs المحظورة</div><div class="text-3xl font-black text-rose-400">{total_banned_ips}</div></div>
            <div class="bg-[#0f172a] border border-slate-800 p-6 rounded-2xl"><div class="text-xs text-slate-400 mb-2">الهجمات المصودة</div><div class="text-3xl font-black text-rose-500">{total_blocked_attacks}</div></div>
            <div class="bg-[#0f172a] border border-slate-800 p-6 rounded-2xl"><div class="text-xs text-slate-400 mb-2">إجمالي الطلبات</div><div class="text-3xl font-black text-emerald-400">{total_inspected_requests}</div></div>
        </div>
        <div class="max-w-7xl w-full mx-auto px-6 mt-8">
            <div class="bg-[#0f172a] border border-slate-800 p-2 rounded-2xl flex gap-2">
                <button onclick="switchDashboardTab('tab-logs')" class="tab-menu-btn bg-blue-600 text-white px-6 py-3 rounded-xl text-xs font-bold cursor-pointer">📊 السجلات الأمنية</button>
                <button onclick="switchDashboardTab('tab-bans')" class="tab-menu-btn text-slate-400 px-6 py-3 rounded-xl text-xs font-bold cursor-pointer">🚫 إدارة الحظر</button>
                <button onclick="switchDashboardTab('tab-staff')" class="tab-menu-btn text-slate-400 px-6 py-3 rounded-xl text-xs font-bold cursor-pointer">👥 فريق العمل</button>
                <button onclick="switchDashboardTab('tab-settings')" class="tab-menu-btn text-slate-400 px-6 py-3 rounded-xl text-xs font-bold cursor-pointer">⚙️ الإعدادات</button>
            </div>
        </div>
        <main class="max-w-7xl w-full mx-auto px-6 my-8 flex-1">
            <div id="tab-logs" class="dashboard-tab grid grid-cols-1 lg:grid-cols-3 gap-6">
                <div class="lg:col-span-2 bg-[#0f172a] border border-slate-800 rounded-3xl p-6"><h3 class="text-sm font-bold text-white mb-4">📋 سجلات WAF الحية</h3><div class="overflow-x-auto max-h-[500px]"><table class="w-full text-right"><thead><tr class="border-b border-slate-800 text-slate-400 text-xs"><th class="py-3 px-4">التوقيت</th><th class="py-3 px-4">الحالة</th><th class="py-3 px-4">المسار</th><th class="py-3 px-4">نوع الهجوم</th><th class="py-3 px-4">IP</th></tr></thead><tbody>{logs_table_html}</tbody></table></div></div>
                <div class="bg-[#0f172a] border border-slate-800 rounded-3xl p-6"><h3 class="text-sm font-bold text-white mb-4">👀 الزوار الحيون</h3><div class="overflow-x-auto max-h-[500px]"><table class="w-full text-right"><thead><tr class="border-b border-slate-800 text-slate-400 text-xs"><th class="py-3 px-4">الوقت</th><th class="py-3 px-4">الصفحة</th><th class="py-3 px-4">الـ IP</th></tr></thead><tbody>{visitors_table_html}</tbody></table></div></div>
            </div>
            <div id="tab-bans" class="dashboard-tab hidden grid grid-cols-1 md:grid-cols-2 gap-6">
                <div class="bg-[#0f172a] border border-slate-800 rounded-3xl p-6"><h3 class="text-sm font-bold text-white mb-4">🚫 حظر IP يدوي</h3><form action="/admin/manual-block-ip" method="post" class="space-y-4"><input type="text" name="ip" placeholder="IP" required class="w-full bg-[#030712] border border-slate-800 rounded-xl px-4 py-3 text-sm text-white"><input type="text" name="reason" placeholder="السبب" required class="w-full bg-[#030712] border border-slate-800 rounded-xl px-4 py-3 text-sm text-white"><button type="submit" class="w-full bg-rose-600 text-white font-bold py-3 rounded-xl">حظر</button></form></div>
                <div class="bg-[#0f172a] border border-slate-800 rounded-3xl p-6"><h3 class="text-sm font-bold text-white mb-4">🛡️ الـ IPs المحظورة</h3><div class="overflow-x-auto max-h-[350px]"><table class="w-full text-right"><thead><tr class="border-b border-slate-800 text-slate-400 text-xs"><th class="py-3 px-4">الـ IP</th><th class="py-3 px-4">السبب</th><th class="py-3 px-4">الخطورة</th><th class="py-3 px-4">التوقيت</th><th class="py-3 px-4">إجراء</th></tr></thead><tbody>{blacklist_table_html}</tbody></table></div></div>
            </div>
            <div id="tab-staff" class="dashboard-tab hidden space-y-6">
                <div class="bg-[#0f172a] border border-slate-800 rounded-3xl p-6"><h3 class="text-sm font-bold text-white mb-4">➕ إضافة موظف</h3><form action="/admin/add-operator" method="post" class="grid grid-cols-1 md:grid-cols-4 gap-4 items-end"><input type="text" name="operator_name" placeholder="الاسم" required class="bg-[#030712] border border-slate-800 rounded-xl px-4 py-2.5 text-sm text-white"><input type="email" name="operator_email" placeholder="الإيميل" required class="bg-[#030712] border border-slate-800 rounded-xl px-4 py-2.5 text-sm text-white"><select name="security_role" class="bg-[#030712] border border-slate-800 rounded-xl px-4 py-2.5 text-sm text-white"><option value="SOC Senior">محلل أمني أول</option></select><button type="submit" class="bg-blue-600 text-white font-bold py-2.5 rounded-xl">حفظ</button></form></div>
                <div class="bg-[#0f172a] border border-slate-800 rounded-3xl p-6"><table class="w-full text-right"><thead><tr class="border-b border-slate-800 text-slate-400 text-xs"><th class="py-3 px-4">الاسم</th><th class="py-3 px-4">الإيميل</th><th class="py-3 px-4">الصلاحية</th><th class="py-3 px-4">إجراء</th></tr></thead><tbody>{staff_table_html}</tbody></table></div>
            </div>
            <div id="tab-settings" class="dashboard-tab hidden max-w-xl mx-auto">
                <div class="bg-[#0f172a] border border-slate-800 rounded-3xl p-6"><h3 class="text-sm font-bold text-white mb-4">⚙️ تغيير بيانات المشرف</h3><form action="/admin/update-credentials" method="post" class="space-y-4"><input type="text" name="new_username" required value="{current_admin_name}" class="w-full bg-[#030712] border border-slate-800 rounded-xl px-4 py-3 text-sm text-white"><input type="password" name="new_password" placeholder="كلمة المرور الجديدة" required class="w-full bg-[#030712] border border-slate-800 rounded-xl px-4 py-3 text-sm text-white"><button type="submit" class="w-full bg-blue-600 text-white font-bold py-3 rounded-xl">تحديث</button></form></div>
            </div>
        </main>
    </body></html>
    """)

@app.post("/admin/manual-block-ip")
async def admin_manual_block(request: Request, ip: str = Form(...), reason: str = Form(...)):
    if request.cookies.get("session") != "authenticated_admin_token":
        return RedirectResponse(url="/login")
    db_conn = sqlite3.connect(DATABASE_FILENAME)
    db_cursor = db_conn.cursor()
    db_cursor.execute("INSERT OR REPLACE INTO global_ip_blacklist (ip_address, block_reason, threat_level, banned_timestamp, violation_count) VALUES (?, ?, 'MANUAL', ?, 1)", (ip, reason, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    db_conn.commit()
    db_conn.close()
    return RedirectResponse(url="/soc-dashboard", status_code=303)

@app.get("/admin/unblock-ip/{ip_addr:path}")
async def admin_unblock_ip_route(request: Request, ip_addr: str):
    if request.cookies.get("session") != "authenticated_admin_token":
        return RedirectResponse(url="/login")
    db_conn = sqlite3.connect(DATABASE_FILENAME)
    db_cursor = db_conn.cursor()
    db_conn.execute("DELETE FROM global_ip_blacklist WHERE ip_address = ?", (ip_addr,))
    db_conn.commit()
    db_conn.close()
    return RedirectResponse(url="/soc-dashboard", status_code=303)

@app.post("/admin/add-operator")
async def admin_add_operator_route(request: Request, operator_name: str = Form(...), operator_email: str = Form(...), security_role: str = Form(...)):
    if request.cookies.get("session") != "authenticated_admin_token":
        return RedirectResponse(url="/login")
    db_conn = sqlite3.connect(DATABASE_FILENAME)
    db_cursor = db_conn.cursor()
    db_cursor.execute("INSERT INTO soc_operators_staff (operator_name, operator_email, security_role, account_state, joined_date) VALUES (?, ?, ?, ?, ?)",
                   (operator_name, operator_email, security_role, "نشط", datetime.now().strftime("%Y-%m-%d")))
    db_conn.commit()
    db_conn.close()
    return RedirectResponse(url="/soc-dashboard", status_code=303)

@app.get("/admin/remove-staff/{operator_id}")
async def admin_remove_staff_route(request: Request, operator_id: int):
    if request.cookies.get("session") != "authenticated_admin_token":
        return RedirectResponse(url="/login")
    db_conn = sqlite3.connect(DATABASE_FILENAME)
    db_cursor = db_conn.cursor()
    db_cursor.execute("DELETE FROM soc_operators_staff WHERE operator_id = ?", (operator_id,))
    db_conn.commit()
    db_conn.close()
    return RedirectResponse(url="/soc-dashboard", status_code=303)

@app.post("/admin/update-credentials")
async def admin_update_creds_route(request: Request, new_username: str = Form(...), new_password: str = Form(...)):
    if request.cookies.get("session") != "authenticated_admin_token":
        return RedirectResponse(url="/login")
    db_conn = sqlite3.connect(DATABASE_FILENAME)
    db_cursor = db_conn.cursor()
    db_cursor.execute("UPDATE system_core_settings SET master_username = ?, master_password_secret = ?, last_configuration_update = ? WHERE config_id = 1",
                   (new_username, new_password, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    db_conn.commit()
    db_conn.close()
    return HTMLResponse(content="<script>alert('تم التحديث بنجاح! سجل دخولك مجدداً.'); window.location.href='/login';</script>")

@app.get("/admin/purge-all-logs")
async def admin_purge_all_route(request: Request):
    if request.cookies.get("session") != "authenticated_admin_token":
        return RedirectResponse(url="/login")
    db_conn = sqlite3.connect(DATABASE_FILENAME)
    db_cursor = db_conn.cursor()
    db_cursor.execute("DELETE FROM waf_security_logs")
    db_cursor.execute("DELETE FROM portal_visitor_analytics")
    db_cursor.execute("DELETE FROM global_ip_blacklist")
    db_conn.commit()
    db_conn.close()
    return HTMLResponse(content="<script>alert('تم تصفير السجلات بنجاح!'); window.location.href='/soc-dashboard';</script>")