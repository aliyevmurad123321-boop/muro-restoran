from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
import json, os, hashlib, hmac, secrets, time
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)

# ── Güclü, random session açarı ──────────────────────────────────────────────
# Hər server başladıqda EYNİ açar oxunur (fayldan) — dəyişmir, amma random-dur
SECRET_KEY_FILE = os.path.join(os.path.dirname(__file__), "data", ".secret_key")
os.makedirs(os.path.dirname(SECRET_KEY_FILE), exist_ok=True)

if os.path.exists(SECRET_KEY_FILE):
    with open(SECRET_KEY_FILE) as f:
        app.secret_key = f.read().strip()
else:
    app.secret_key = secrets.token_hex(32)   # 256-bit random key
    with open(SECRET_KEY_FILE, "w") as f:
        f.write(app.secret_key)

# Session parametrləri
app.config["SESSION_COOKIE_HTTPONLY"]  = True    # JS-dən gizlən
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"   # CSRF qorunması
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(hours=4)

# ── Fayl yolları ──────────────────────────────────────────────────────────────
DATA_DIR          = os.path.join(os.path.dirname(__file__), "data")
MENU_FILE         = os.path.join(DATA_DIR, "menu.json")
ORDERS_FILE       = os.path.join(DATA_DIR, "orders.json")
RESERVATIONS_FILE = os.path.join(DATA_DIR, "reservations.json")
SETTINGS_FILE     = os.path.join(DATA_DIR, "settings.json")
LOG_FILE          = os.path.join(DATA_DIR, "security.log")
LOCKOUT_FILE      = os.path.join(DATA_DIR, ".lockout.json")

# ── Şifrə funksiyaları (PBKDF2-SHA256 — bank səviyyəsində) ───────────────────
def hash_password(plain: str) -> str:
    """Şifrəni 310.000 iterasiya ilə hashla, hər dəfə fərqli salt."""
    salt = secrets.token_hex(16)
    dk   = hashlib.pbkdf2_hmac("sha256", plain.encode(), salt.encode(), 310_000)
    return f"pbkdf2$310000${salt}${dk.hex()}"

def verify_password(plain: str, stored: str) -> bool:
    """Timing attack-a qarşı qorunan müqayisə."""
    try:
        _, iterations, salt, dk_hex = stored.split("$")
        dk = hashlib.pbkdf2_hmac("sha256", plain.encode(), salt.encode(), int(iterations))
        return hmac.compare_digest(dk.hex(), dk_hex)
    except Exception:
        return False

def is_hashed(stored: str) -> bool:
    return stored.startswith("pbkdf2$")

# ── Brute-force qorunması ─────────────────────────────────────────────────────
MAX_ATTEMPTS   = 5      # Maksimum yanlış cəhd
LOCKOUT_SECS   = 300    # 5 dəqiqə kilidlənmə
ATTEMPT_WINDOW = 600    # 10 dəqiqə ərzindəki cəhdlər sayılır

def load_lockout() -> dict:
    if os.path.exists(LOCKOUT_FILE):
        with open(LOCKOUT_FILE) as f:
            return json.load(f)
    return {}

def save_lockout(data: dict):
    with open(LOCKOUT_FILE, "w") as f:
        json.dump(data, f)

def get_client_ip() -> str:
    return request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()

def is_locked_out(ip: str):
    """(kilidlidirmi, neçə saniyə qalır)"""
    data = load_lockout()
    rec  = data.get(ip, {})
    now  = time.time()
    locked_until = rec.get("locked_until", 0)
    if locked_until and now < locked_until:
        return True, int(locked_until - now)
    attempts = [t for t in rec.get("attempts", []) if now - t < ATTEMPT_WINDOW]
    if len(attempts) >= MAX_ATTEMPTS:
        locked_until = now + LOCKOUT_SECS
        data[ip] = {"attempts": attempts, "locked_until": locked_until}
        save_lockout(data)
        return True, int(LOCKOUT_SECS)
    return False, 0

def record_attempt(ip: str, success: bool):
    data = load_lockout()
    now  = time.time()
    rec  = data.get(ip, {})
    attempts = [t for t in rec.get("attempts", []) if now - t < ATTEMPT_WINDOW]
    if success:
        data[ip] = {}
    else:
        attempts.append(now)
        data[ip] = {"attempts": attempts, "locked_until": rec.get("locked_until", 0)}
    save_lockout(data)

# ── Loq sistemi ───────────────────────────────────────────────────────────────
def write_log(event: str, ip: str, detail: str = ""):
    ts   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {event:20s} | IP: {ip:20s} | {detail}\n"
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line)

def load_logs(n: int = 40):
    if not os.path.exists(LOG_FILE):
        return []
    with open(LOG_FILE, encoding="utf-8") as f:
        lines = f.readlines()
    return list(reversed(lines[-n:]))

# ── JSON köməkçiləri ──────────────────────────────────────────────────────────
def load_json(path, default):
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    return default

def save_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def get_settings():
    s = load_json(SETTINGS_FILE, {
        "name":     "Muro Restoran",
        "phone":    "+994 50 123 45 67",
        "address":  "Bakı, Neftçilər prospekti 10",
        "hours":    "10:00 – 23:00",
        "password": "admin123"
    })
    if not is_hashed(s.get("password", "")):
        s["password"] = hash_password(s["password"])
        save_json(SETTINGS_FILE, s)
    return s

def get_menu():
    return load_json(MENU_FILE, {
        "Əsas Yeməklər": [
            {"id":1,"name":"Lula Kebab",      "price":12.00,"desc":"Ənənəvi Azərbaycan lula kebabı","emoji":"🍢"},
            {"id":2,"name":"Tika Kebab",       "price":14.00,"desc":"Seçilmiş ət parçaları",          "emoji":"🥩"},
            {"id":3,"name":"Balıq Qızartması", "price":16.00,"desc":"Təzə çay balığı",                "emoji":"🐟"},
        ],
        "Salatlar": [
            {"id":4,"name":"Şoban Salatı","price":5.00,"desc":"Pomidor, xiyar, soğan","emoji":"🥗"},
            {"id":5,"name":"Cəzər Salatı","price":4.50,"desc":"Koreya üslubunda kök salatı","emoji":"🥕"},
        ],
        "İçkilər": [
            {"id":6,"name":"Ayran","price":2.00,"desc":"Ev ayranı","emoji":"🥛"},
            {"id":7,"name":"Kompot","price":2.50,"desc":"Meyvə kompotu","emoji":"🍹"},
            {"id":8,"name":"Çay","price":1.50,"desc":"Azərbaycan çayı","emoji":"☕"},
        ],
        "Şirniyyat": [
            {"id":9, "name":"Baklava",  "price":6.00,"desc":"Əl işi baklava","emoji":"🍯"},
            {"id":10,"name":"Şəkərbura","price":4.00,"desc":"Ənənəvi şəkərbura","emoji":"🥮"},
        ]
    })

def get_orders():       return load_json(ORDERS_FILE, [])
def get_reservations(): return load_json(RESERVATIONS_FILE, [])

# ── Admin dekoratoru ──────────────────────────────────────────────────────────
def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("admin"):
            write_log("UNAUTH_ACCESS", get_client_ip(), f"url={request.path}")
            return redirect(url_for("admin_login"))
        if session.get("admin_ip") != get_client_ip():
            write_log("SESSION_HIJACK", get_client_ip(), "IP dəyişdi — session ləğv edildi")
            session.clear()
            flash("⚠️ Sessiyanız başqa IP-dən açıldı. Yenidən daxil olun.", "error")
            return redirect(url_for("admin_login"))
        return f(*args, **kwargs)
    return decorated

# ═══════════════════════════════════════════════════════════════════════════════
#  MÜŞTƏRİ SƏHİFƏLƏRİ
# ═══════════════════════════════════════════════════════════════════════════════
@app.route("/")
def index():
    return render_template("index.html", settings=get_settings())

@app.route("/menu")
def menu():
    return render_template("menu.html", menu=get_menu(), settings=get_settings())

@app.route("/order", methods=["GET","POST"])
def order():
    if request.method == "POST":
        data = request.get_json()
        orders = get_orders()
        new_order = {
            "id":     len(orders)+1,
            "name":   data.get("name"),
            "phone":  data.get("phone"),
            "table":  data.get("table"),
            "items":  data.get("items",[]),
            "total":  data.get("total"),
            "note":   data.get("note",""),
            "status": "Gözləyir",
            "time":   datetime.now().strftime("%d.%m.%Y %H:%M")
        }
        orders.append(new_order)
        save_json(ORDERS_FILE, orders)
        return jsonify({"success":True,"order_id":new_order["id"]})
    return render_template("order.html", menu=get_menu(), settings=get_settings())

@app.route("/reservation", methods=["GET","POST"])
def reservation():
    if request.method == "POST":
        data = request.form
        reservations = get_reservations()
        new_res = {
            "id":      len(reservations)+1,
            "name":    data.get("name"),
            "phone":   data.get("phone"),
            "date":    data.get("date"),
            "time":    data.get("time"),
            "guests":  data.get("guests"),
            "note":    data.get("note",""),
            "status":  "Təsdiqlənmədi",
            "created": datetime.now().strftime("%d.%m.%Y %H:%M")
        }
        reservations.append(new_res)
        save_json(RESERVATIONS_FILE, reservations)
        flash("Rezervasiya müraciətiniz qəbul edildi! Tezliklə əlaqə saxlayacağıq.","success")
        return redirect(url_for("reservation"))
    return render_template("reservation.html", settings=get_settings())

# ═══════════════════════════════════════════════════════════════════════════════
#  ADMİN — GİRİŞ
# ═══════════════════════════════════════════════════════════════════════════════
@app.route("/admin", methods=["GET","POST"])
def admin_login():
    ip = get_client_ip()
    locked, secs = is_locked_out(ip)
    if locked:
        write_log("BLOCKED", ip, f"{secs}s kilidlənmə qalır")
        flash(f"⛔ Çox cəhd etdiniz! {secs//60} dəqiqə {secs%60} saniyə sonra yenidən cəhd edin.", "error")
        return render_template("admin_login.html", locked=True, wait=secs, settings=get_settings())

    if request.method == "POST":
        pw       = request.form.get("password","")
        settings = get_settings()
        if verify_password(pw, settings["password"]):
            record_attempt(ip, success=True)
            session.clear()
            session["admin"]    = True
            session["admin_ip"] = ip
            session["login_at"] = datetime.now().isoformat()
            session.permanent   = True
            write_log("LOGIN_OK", ip, "Admin uğurla daxil oldu")
            return redirect(url_for("admin_dashboard"))
        else:
            record_attempt(ip, success=False)
            data     = load_lockout()
            attempts = len([t for t in data.get(ip,{}).get("attempts",[])
                            if time.time()-t < ATTEMPT_WINDOW])
            remaining = MAX_ATTEMPTS - attempts
            write_log("LOGIN_FAIL", ip, f"Yanlış şifrə — {attempts}/{MAX_ATTEMPTS}")
            if remaining > 0:
                flash(f"❌ Şifrə yanlışdır! {remaining} cəhd qalır.", "error")
            else:
                flash(f"⛔ {LOCKOUT_SECS//60} dəqiqəlik kilidləndiniz!", "error")

    return render_template("admin_login.html", locked=False, wait=0, settings=get_settings())

@app.route("/admin/logout")
def admin_logout():
    write_log("LOGOUT", get_client_ip(), "Admin çıxış etdi")
    session.clear()
    return redirect(url_for("index"))

# ═══════════════════════════════════════════════════════════════════════════════
#  ADMİN — DASHBOARD
# ═══════════════════════════════════════════════════════════════════════════════
@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():
    orders       = get_orders()
    reservations = get_reservations()
    pending_orders = [o for o in orders if o["status"]=="Gözləyir"]
    pending_res    = [r for r in reservations if r["status"]=="Təsdiqlənmədi"]
    total_revenue  = sum(float(o.get("total",0)) for o in orders)
    logs = load_logs(30)
    return render_template("admin_dashboard.html",
        orders=orders, reservations=reservations,
        pending_orders=pending_orders, pending_res=pending_res,
        total_revenue=total_revenue, settings=get_settings(), logs=logs)

# ═══════════════════════════════════════════════════════════════════════════════
#  ADMİN — MENYU
# ═══════════════════════════════════════════════════════════════════════════════
@app.route("/admin/menu", methods=["GET","POST"])
@admin_required
def admin_menu():
    if request.method == "POST":
        action   = request.form.get("action")
        menu     = get_menu()
        category = request.form.get("category","")
        if action == "add":
            if category not in menu:
                menu[category] = []
            all_ids = [item["id"] for cat in menu.values() for item in cat]
            new_id  = max(all_ids, default=0)+1
            menu[category].append({
                "id":    new_id,
                "name":  request.form.get("name"),
                "price": float(request.form.get("price",0)),
                "desc":  request.form.get("desc",""),
                "emoji": request.form.get("emoji","🍽️")
            })
            write_log("MENU_ADD", get_client_ip(), request.form.get("name",""))
        elif action == "delete":
            item_id = int(request.form.get("item_id"))
            for cat in menu:
                menu[cat] = [i for i in menu[cat] if i["id"]!=item_id]
            write_log("MENU_DEL", get_client_ip(), f"id={item_id}")
        elif action == "add_category":
            new_cat = request.form.get("new_category","").strip()
            if new_cat and new_cat not in menu:
                menu[new_cat] = []
        save_json(MENU_FILE, menu)
        flash("Menyu yeniləndi!","success")
        return redirect(url_for("admin_menu"))
    return render_template("admin_menu.html", menu=get_menu(), settings=get_settings())

# ═══════════════════════════════════════════════════════════════════════════════
#  ADMİN — SİFARİŞLƏR
# ═══════════════════════════════════════════════════════════════════════════════
@app.route("/admin/orders")
@admin_required
def admin_orders():
    return render_template("admin_orders.html", orders=get_orders(), settings=get_settings())

@app.route("/admin/orders/update", methods=["POST"])
@admin_required
def update_order():
    order_id   = int(request.form.get("order_id"))
    new_status = request.form.get("status")
    orders = get_orders()
    for o in orders:
        if o["id"]==order_id:
            o["status"]=new_status; break
    save_json(ORDERS_FILE, orders)
    write_log("ORDER_UPDATE", get_client_ip(), f"id={order_id} → {new_status}")
    flash("Sifariş statusu yeniləndi!","success")
    return redirect(url_for("admin_orders"))

# ═══════════════════════════════════════════════════════════════════════════════
#  ADMİN — REZERVASİYALAR
# ═══════════════════════════════════════════════════════════════════════════════
@app.route("/admin/reservations")
@admin_required
def admin_reservations():
    return render_template("admin_reservations.html", reservations=get_reservations(), settings=get_settings())

@app.route("/admin/reservations/update", methods=["POST"])
@admin_required
def update_reservation():
    res_id     = int(request.form.get("res_id"))
    new_status = request.form.get("status")
    reservations = get_reservations()
    for r in reservations:
        if r["id"]==res_id:
            r["status"]=new_status; break
    save_json(RESERVATIONS_FILE, reservations)
    write_log("RES_UPDATE", get_client_ip(), f"id={res_id} → {new_status}")
    flash("Rezervasiya statusu yeniləndi!","success")
    return redirect(url_for("admin_reservations"))

# ═══════════════════════════════════════════════════════════════════════════════
#  ADMİN — PARAMETRLƏR + ŞİFRƏ DƏYİŞ
# ═══════════════════════════════════════════════════════════════════════════════
@app.route("/admin/settings", methods=["GET","POST"])
@admin_required
def admin_settings():
    if request.method == "POST":
        settings    = get_settings()
        current_pw  = request.form.get("current_password","")
        new_pw      = request.form.get("new_password","").strip()
        confirm_pw  = request.form.get("confirm_password","").strip()

        # Cari şifrəni mütləq doğrula
        if not verify_password(current_pw, settings["password"]):
            write_log("PW_CHANGE_FAIL", get_client_ip(), "Cari şifrə yanlış")
            flash("❌ Cari şifrəniz yanlışdır!", "error")
            return redirect(url_for("admin_settings"))

        settings["name"]    = request.form.get("name","")
        settings["phone"]   = request.form.get("phone","")
        settings["address"] = request.form.get("address","")
        settings["hours"]   = request.form.get("hours","")

        if new_pw:
            if len(new_pw) < 8:
                flash("❌ Yeni şifrə ən az 8 simvol olmalıdır!", "error")
                return redirect(url_for("admin_settings"))
            if new_pw != confirm_pw:
                flash("❌ Yeni şifrələr uyğun gəlmir!", "error")
                return redirect(url_for("admin_settings"))
            settings["password"] = hash_password(new_pw)
            write_log("PW_CHANGED", get_client_ip(), "Şifrə uğurla dəyişdirildi")
            flash("✅ Parametrlər və şifrə uğurla yeniləndi!","success")
        else:
            flash("✅ Parametrlər yadda saxlandı!","success")

        save_json(SETTINGS_FILE, settings)
        return redirect(url_for("admin_settings"))

    login_time = session.get("login_at","Bilinmir")
    return render_template("admin_settings.html", settings=get_settings(), login_time=login_time)

if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=False, host="0.0.0.0", port=port)
