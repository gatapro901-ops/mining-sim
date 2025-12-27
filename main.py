# main.py - High Security Version 🚀
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, make_response, flash
import json, os, random, time
from datetime import datetime, timedelta
import bcrypt
from flask_wtf import CSRFProtect

app = Flask(__name__)

# --- إعدادات الأمان الأساسية ---
# تأكد من تغيير هذه المفاتيح قبل إطلاق الموقع للعامة
app.config['SECRET_KEY'] = os.urandom(32) 
app.secret_key = "any_strong_fallback_key"

# مسارات ملفات البيانات
USERS_FILE = "users.json"
ITEMS_FILE = "items.json"
TASKS_FILE = "tasks.json"

# تفعيل حماية CSRF
csrf = CSRFProtect(app)

# إعدادات حماية الجلسة (Session) والكوكيز
app.config.update(
    SESSION_COOKIE_SECURE=False, # اجعلها True لو استخدمت HTTPS (مثل Cloudflare)
    SESSION_COOKIE_HTTPONLY=True, # تمنع سرقة الكوكيز عبر JavaScript
    SESSION_COOKIE_SAMESITE='Lax', # تمنع هجمات الـ CSRF
    PERMANENT_SESSION_LIFETIME=timedelta(days=1) # صلاحية الدخول يوم واحد
)

# --- إضافة دروع الحماية (Security Headers) ---
# هذا الجزء هو اللي هيصلح أخطاء فحص Nikto اللي ظهرتلك
@app.after_request
def add_security_headers(response):
    # حماية ضد الـ XSS في المتصفحات القديمة
    response.headers['X-XSS-Protection'] = '1; mode=block'
    # منع المتصفح من تخمين نوع الملفات (يحمي من رفع ملفات خبيثة)
    response.headers['X-Content-Type-Options'] = 'nosniff'
    # حماية ضد الـ Clickjacking (منع وضع موقعك في إطار iframe)
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    # حماية CSP: تمنع حقن السكربتات الخارجية (تسمح فقط بالسكربتات من موقعك)
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';"
    # حماية الخصوصية (لا ترسل عنوان موقعك عند الضغط على روابط خارجية)
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

# ثابت أمان تسجيل الدخول
MAX_FAILED_ATTEMPTS = 5
LOCK_DURATION_MINUTES = 5

# --- بداية الأكواد والوظائف (الـ Routes) ---

# ---------- Helper functions ----------
# المهام الافتراضية
DEFAULT_TASKS = [
    {"title": "أول تسجيل الدخول", "reward": 0.00000006, "type":"btc", "condition":"first_login"},
    {"title": "اشتري ثلاثة أجهزة", "reward": 0.00000020, "type":"btc", "condition":"buy_3_items"},
    {"title": "اشتري خمسة أجهزة", "reward": 0.00000100, "type":"btc", "condition":"buy_5_items"},
    {"title": "اشتري عشرة أجهزة", "reward": 0.00000175, "type":"btc", "condition":"buy_10_items"},
    {"title": "اشتري عشرون جهاز", "reward": 0.00000250, "type":"btc", "condition":"buy_20_items"},
    {"title": "اشتري ثلاثون جهاز", "reward": 0.00000325, "type":"btc", "condition":"buy_30_items"},
    {"title": "اشتري خمسون جهاز", "reward": 0.00000500, "type":"btc", "condition":"buy_50_items"},
    {"title": "اشتري مائة جهاز", "reward": 0.00001000, "type":"btc", "condition":"buy_100_items"},
    {"title": "سجل الدخول يوميا لمدة أسبوع", "reward": 900, "type":"xp", "condition":"login_7_days"},
    {"title": "سجل الدخول يوميا لمدة شهر", "reward": 5000, "type":"xp", "condition":"login_30_days"},
]

def load_tasks():
    if not os.path.exists(TASKS_FILE):
        with open(TASKS_FILE, "w", encoding="utf-8") as f:
            json.dump({}, f, indent=4, ensure_ascii=False)

    try:
        with open(TASKS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)

            # لو الملف اتحول لقائمة بالغلط → نصلحه
            if isinstance(data, list):
                return {}

            return data
    except:
        return {}

def save_tasks(tasks):
    with open(TASKS_FILE, "w", encoding="utf-8") as f:
        json.dump(tasks, f, indent=4, ensure_ascii=False)
# تعطي المستخدم مهامه الافتراضية لو جديد
def get_user_tasks(username):
    tasks_data = load_tasks()

    username = username.strip().lower()  # توحيد الاسم للحروف الصغيرة

    if username not in tasks_data:
        # نسخ المهام الافتراضية
        tasks_data[username] = []
        for t in DEFAULT_TASKS:
            tasks_data[username].append({
                "title": t["title"],
                "reward": float(t["reward"]),  # لتكون 0.00000000
                "type": t["type"],
                "condition": t["condition"],
                "completed": False
            })
        save_tasks(tasks_data)

    # تأكد إن كل مهمة عندها completed
    for t in tasks_data[username]:
        if "completed" not in t:
            t["completed"] = False

    save_tasks(tasks_data)  # تحديث الملف لو فيه أي حاجة جديدة

    return tasks_data[username]

# تعليم مهمة كمكتملة
def mark_task_completed(username, condition):
    tasks_data = load_tasks()
    user_tasks = tasks_data.get(username, [])
    users = load_users()
    user = next((u for u in users if u["username"] == username), None)
    
    if not user:
        return False, "المستخدم غير موجود"
    
    task = next((t for t in user_tasks if t.get("condition") == condition), None)
    if not task:
        return False, "المهمة غير موجود"
    
    if task.get("completed", False):
        return False, "المهمة مكتملة مسبقًا"  # منع مضاعفة المكافأة

    # علامة المهمة كمكتملة
    task["completed"] = True
    task["last_done"] = datetime.now().strftime("%Y-%m-%d")

    # إضافة المكافأة
    if task["type"] == "btc":
        user["balance"] = float(user.get("balance", 0)) + float(task.get("reward", 0))
        user["balance"] = float(f"{user['balance']:.8f}")
    elif task["type"] == "xp":
        user["xp"] = int(user.get("xp", 0)) + int(task.get("reward", 0))
        user["rank"] = calculate_rank(user["xp"])

    tasks_data[username] = user_tasks
    save_tasks(tasks_data)
    save_users(users)

    return True, f"تم إكمال المهمة: {task.get('title','(بدون عنوان)')} 🎉"



def load_users():
    if not os.path.exists(USERS_FILE):
        with open(USERS_FILE, "w") as f:
            json.dump([], f)
    with open(USERS_FILE, "r") as f:
        try:
            return json.load(f)
        except:
            return []

def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f, indent=4)

def find_user(username):
    if username is None:
        return None
    username = username.strip()
    users = load_users()
    for u in users:
        if u.get("username","").strip() == username:
            return u
    return None

def update_user(user):
    users = load_users()
    for i,u in enumerate(users):
        if u.get("username","").strip() == user.get("username","").strip():
            users[i] = user
            break
    else:
        users.append(user)
    save_users(users)

def delete_user_by_name(username: str):
    username_clean = username.strip().lower()
    # حذف المستخدم
    users = load_users()
    users = [u for u in users if u.get("username","").strip().lower() != username_clean]
    save_users(users)

    # حذف الأجهزة المرتبطة بالمستخدم
    items = load_items()
    items = [i for i in items if i.get("owner","").strip().lower() != username_clean]
    save_items(items)

    # حذف المهام الخاصة بالمستخدم
    tasks = load_tasks()
    if username_clean in tasks:
        del tasks[username_clean]
        save_tasks(tasks)

def calculate_rank(xp):
    try: xp=int(xp)
    except: xp=0
    if 0 <= xp <= 12000: return "مبتدأ"
    elif 12001 <= xp <= 25000: return "متوسط"
    elif 25001 <= xp <= 60000: return "خبير"
    elif 60001 <= xp <= 120000: return "أسطوري"
    return "مبتدأ"

def check_task_condition(username, condition):
    """
    تحقق من شرط المهمة للمستخدم.
    ترجع (True, "") لو الشرط متحقق، أو (False, رسالة_خطأ) لو مش متحقق.
    """

    users = load_users()
    user = next((u for u in users if u.get("username") == username), None)
    if not user:
        return False, "المستخدم غير موجود"

    # أول تسجيل دخول
    if condition == "first_login":
        return True, ""

    # شراء أجهزة
    if condition.startswith("buy_"):
        count = int(condition.replace("buy_", "").replace("_items", ""))
        items = load_items()
        owned = [i for i in items if i.get("owner") == username]
        if len(owned) >= count:
            return True, ""
        else:
            return False, f"يجب شراء {count} أجهزة أولًا"

    # تسجيل دخول 7 أيام
    if condition == "login_7_days":
        if user.get("login_streak", 0) >= 7:
            return True, ""
        else:
            return False, "يجب تسجيل الدخول لمدة 7 أيام متتالية"

    # تسجيل دخول 30 يوم
    if condition == "login_30_days":
        if user.get("login_streak", 0) >= 30:
            return True, ""
        else:
            return False, "يجب تسجيل الدخول لمدة 30 يوم متتالية"

    # أي شرط آخر غير معروف
    return False, "شرط المهمة غير معروف"

def update_user_tasks(username):
    tasks_data = load_tasks()
    user_tasks = tasks_data.get(username, [])

    # لو المستخدم ملوش مهام → نعمله نسخة جديدة من DEFAULT_TASKS
    if not user_tasks:
        user_tasks = [dict(t, completed=False) for t in DEFAULT_TASKS]
        tasks_data[username] = user_tasks

    users = load_users()
    user = next((u for u in users if u.get("username") == username), None)
    if not user:
        return []

    messages = []
    today = datetime.now().date()

    for task in user_tasks:
        # إعادة تعيين المهام اليومية لو لم تُنجز اليوم
        if task.get("type") == "daily":
            last_done_str = task.get("last_done")
            last_done_date = None
            if isinstance(last_done_str, str) and last_done_str:
                try:
                    last_done_date = datetime.strptime(last_done_str, "%Y-%m-%d").date()
                except:
                    last_done_date = None

            if last_done_date != today:
                task["completed"] = False  # bool مضبوط

        # لو المهمة مكتملة مسبقًا → نعدي
        if bool(task.get("completed", False)):
            continue

        # تحقق الشرط
        condition_ok, _ = check_task_condition(username, task.get("condition", ""))
        if condition_ok:
            task["completed"] = True  # bool
            task["last_done"] = today.strftime("%Y-%m-%d")  # str

            # إضافة المكافأة
            if task.get("type") == "btc":
                user["balance"] = float(user.get("balance", 0)) + float(task.get("reward", 0))
                user["balance"] = float(f"{user['balance']:.8f}")
            elif task.get("type") == "xp":
                user["xp"] = int(user.get("xp", 0)) + int(task.get("reward", 0))
                user["rank"] = calculate_rank(user["xp"])

            messages.append(f"تم إكمال المهمة: {task.get('title','(بدون عنوان)')} 🎉")

    # حفظ التغييرات
    tasks_data[username] = user_tasks
    save_tasks(tasks_data)
    save_users(users)

    return messages

def check_auto_tasks(username):
    today = datetime.now().date()
    users = load_users()
    user = next((u for u in users if u.get("username") == username), None)
    if not user:
        return

    all_tasks = load_tasks()
    tasks = all_tasks.get(username, [])

    changed = False

    for task in tasks:
        if task.get("type") == "daily":
            last_done_str = task.get("last_done")
            last_done_date = None
            if last_done_str:
                try:
                    last_done_date = datetime.strptime(last_done_str, "%Y-%m-%d").date()
                except:
                    last_done_date = None

            if last_done_date != today:
                task["completed"] = False
                changed = True

    if changed:
        all_tasks[username] = tasks
        save_tasks(all_tasks)

    # تنفيذ أول تسجيل دخول بدون مضاعفة المكافأة
    mark_task_completed(username, "first_login")

    # تنفيذ مهام شراء الأجهزة
    counts = [3,5,10,20,30,50,100]
    items = user.get("items", [])
    for count in counts:
        if len(items) >= count:
            mark_task_completed(username, f"buy_{count}_items")

    # تسجيل الدخول اليومي
    last_login = user.get("last_login")
    if last_login:
        last_date = datetime.fromisoformat(last_login).date()
        delta = (today - last_date).days
        if delta >= 1:
            streak = user.get("login_streak", 0) + 1
            user["login_streak"] = streak
            save_users(users)

            if streak >= 7:
                mark_task_completed(username, "login_7_days")
            if streak >= 30:
                mark_task_completed(username, "login_30_days")
    else:
        user["login_streak"] = 1
        save_users(users)

    # تحديث آخر دخول
    user["last_login"] = datetime.now().isoformat()
    save_users(users)

def give_reward(username, condition):
    tasks = get_user_tasks(username)
    users = load_users()

    user = next((u for u in users if u["username"] == username), None)
    if not user:
        return

    task = next((t for t in tasks if t["condition"] == condition), None)
    if not task:
        return

    reward = task["reward"]

    if task["type"] == "btc":
        user["balance"] = float(user.get("balance", 0)) + float(reward)
        user["balance"] = float(f"{user['balance']:.8f}")

    elif task["type"] == "xp":
        user["xp"] = int(user.get("xp", 0)) + int(reward)
        user["rank"] = calculate_rank(user["xp"])

    save_users(users)

def ensure_user_tasks(username):
    tasks = load_tasks()

    # لو مفيش مهام للمستخدم
    if username not in tasks:
        with open("default_tasks.json", "r", encoding="utf-8") as f:
            default = json.load(f)

        # ننسخ النسخة الأصلية لكل يوزر
        tasks[username] = default

        save_tasks(tasks)

    return tasks[username]

# ---------- Store items (base data) ----------
STORE_ITEMS = [
    {"id":1,"name":"Antinminer s19","price":0.00000012,"sat_per_30s":6,"interval":30},
    {"id":2,"name":"Antinminer s19j","price":0.00000050,"sat_per_26s":8,"interval":26},
    {"id":3,"name":"Antinminer s19pro","price":0.00001000,"sat_per_22s":13,"interval":22},
    {"id":4,"name":"Antinminer s19j pro","price":0.00009000,"sat_per_19s":15,"interval":19},
    {"id":5,"name":"Antinminer s21","price":0.00050000,"sat_per_15s":20,"interval":15},
    {"id":6,"name":"Antinminer s21 pro","price":0.00090000,"sat_per_11s":26,"interval":11},
    {"id":7,"name":"Antinminer s23 hydro","price":0.001,"sat_per_8s":30,"interval":8},
    {"id":8,"name":"Antinminer s23 pro hydro","price":0.05,"sat_per_4s":40,"interval":4},
]

# ---------- Items persisted per-user ----------
def load_items():
    if not os.path.exists(ITEMS_FILE):
        with open(ITEMS_FILE,"w") as f:
            json.dump([],f)
    with open(ITEMS_FILE,"r") as f:
        try:
            return json.load(f)
        except:
            return []

def save_items(items):
    with open(ITEMS_FILE,"w") as f:
        json.dump(items,f,indent=4)

def get_user_items(username):
    items = load_items()  # هنا التعديل المهم
    return [i for i in items if str(i.get("owner")) == str(username)]
    
def _derive_sat_and_interval_from_store_item(item):
    # normalize store item to (sat_per_cycle, interval)
    interval = item.get("interval") or 30
    # find any key that starts with 'sat_per'
    sat = None
    for k,v in item.items():
        if isinstance(k,str) and k.startswith("sat_per"):
            try:
                sat = int(v)
                break
            except:
                pass
    if sat is None:
        sat = item.get("sat", 0)
    return sat, int(interval)

def add_item_to_user(username, store_item):
    items = load_items()
    item_copy = {
        "owner": username,
        "store_id": store_item.get("id"),
        "name": store_item.get("name"),
        "price": store_item.get("price"),
        "created_at": datetime.now().isoformat(),
        "active": False,
        "last_tick": None
    }
    sat, interval = _derive_sat_and_interval_from_store_item(store_item)
    item_copy["sat_per_cycle"] = int(sat or 0)
    item_copy["interval"] = int(interval or 30)
    item_copy["id"] = f"{store_item.get('id')}_{int(time.time() * 1000)}"
    items.append(item_copy)
    save_items(items)

def update_user_item(username, item_name, active):
    items = load_items()
    for i in items:
        if i.get("owner")==username and i.get("name")==item_name:
            i["active"]=active
            # initialize last_tick when activating
            if active:
                i["last_tick"] = int(time.time())
            else:
                i["last_tick"] = None
            break
    save_items(items)

# ---------- Utility: safe float comparison for price ----------

def has_enough_balance(user_balance, price):
    try:
        user_sats = int(round(float(user_balance) * 100_000_000))
        price_sats = int(round(float(price) * 100_000_000))
        return user_sats >= price_sats
    except:
        return False
        

# ---------- Routes ----------
@app.route("/")
def welcome():
    users = load_users()
    count = len([u for u in users if u.get("username","").strip() != "gatapro901"])
    return render_template("welcome.html", count=count)

# ---------- Login ----------
@app.route("/login", methods=["GET", "POST"])
def login():
    msg = ""
    a, b = random.randint(1,9), random.randint(1,9)
    captcha_q = f"{a} + {b}"
    captcha_ans = str(a+b)

    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","").strip()
        captcha_input = request.form.get("captcha","").strip()
        captcha_real = request.form.get("captcha_real","").strip()

        if captcha_input == "" or captcha_input != captcha_real:
            msg = "التحقق من الروبوت خاطئ"
            return render_template("login.html", msg=msg, captcha=captcha_q, captcha_real=captcha_ans)

        user = find_user(username)
        if not user:
            msg = "اسم المستخدم غير موجود"
            return render_template("login.html", msg=msg, captcha=captcha_q, captcha_real=captcha_ans)

        # تحقق من القفل المؤقت
        if user.get("lock_until"):
            lock_time = datetime.fromisoformat(user["lock_until"])
            if datetime.now() < lock_time:
                remaining = int((lock_time - datetime.now()).total_seconds() // 60) + 1
                msg = f"الحساب مقفل مؤقتًا. جرب بعد {remaining} دقيقة."
                return render_template("login.html", msg=msg, captcha=captcha_q, captcha_real=captcha_ans)
            else:
                # إعادة تعيين القفل بعد انتهاء الوقت
                user["failed_attempts"] = 0
                user["lock_until"] = ""
                update_user(user)

        # تحقق الباسورد
        if not check_password_hash(user["password"], password):
            user["failed_attempts"] = user.get("failed_attempts",0) + 1
            if user["failed_attempts"] >= MAX_FAILED_ATTEMPTS:
                user["lock_until"] = (datetime.now() + timedelta(minutes=LOCK_DURATION_MINUTES)).isoformat()
                msg = f"وصلت الحد الأقصى لمحاولات الدخول. الحساب مقفل {LOCK_DURATION_MINUTES} دقيقة."
            else:
                msg = f"كلمة المرور خاطئة. حاول مرة أخرى ({user['failed_attempts']}/{MAX_FAILED_ATTEMPTS})"
            update_user(user)
            return render_template("login.html", msg=msg, captcha=captcha_q, captcha_real=captcha_ans)

        # تسجيل الدخول ناجح → إعادة تعيين الفشل
        user["failed_attempts"] = 0
        user["lock_until"] = ""
        user['last_login'] = str(datetime.now())
        update_user(user)
        session['user'] = user.get("username")
        return redirect(url_for("dashboard"))

    return render_template("login.html", msg=msg, captcha=captcha_q, captcha_real=captcha_ans)

# ---------- Register ----------
@app.route("/register", methods=["GET","POST"])
def register():
    msg = ""
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        if username == "":
            msg = "ادخل اسم مستخدم صالح"
            return render_template("register.html", msg=msg)

        if find_user(username):
            msg = "الإسم مستخدم بالفعل"
            return render_template("register.html", msg=msg)

        # تحميل المستخدمين
        users = load_users()

        # إضافة مستخدم جديد بالباسورد المشفر
        users.append({
            "username": username,
            "password": generate_password_hash(password),  # تشفير الباسورد
            "balance": 0.00000012,
            "xp": 0,
            "rank": "مبتدأ",
            "currency": "bitcoin",
            "blocked": False,
            "theme": "light",
            "created_at": datetime.now().isoformat(),
            "last_login": "",
            "mining": False
        })

        save_users(users)
        return redirect(url_for("login"))

    return render_template("register.html", msg=msg)

# ---------- Logout ----------
@app.route("/logout")
def logout():
    if 'user' in session:
        username = session['user']
        items = load_items()
        changed = False
        for item in items:
            if item.get("owner") == username:
                # نحافظ على حالة power_on حسب طلبك؟ الان نوقف التعدين فقط
                item["active"] = False
                item["last_tick"] = None
                changed = True
        if changed:
            save_items(items)
        session.pop('user', None)
    return redirect(url_for("login"))
    
# ---------- Dashboard ----------

@app.route("/dashboard")
def dashboard():
    if 'user' not in session:
        return redirect(url_for("login"))

    username = session['user']
    user = find_user(username)

    # إعداد مستخدم الأدمن الوهمي
    if username == "gatapro901":
        user = {
            "username": "gatapro901",
            "balance": 0.0,
            "xp": 0,
            "rank": "مبتدأ",
            "theme": "light",
            "mining": False
        }

    if user is None:
        session.pop('user', None)
        return redirect(url_for("login"))

    # التحقق التلقائي لمهام المستخدم
    check_auto_tasks(username)

    # **هنا نضيف التحديث التلقائي للمهام وإظهار الرسائل**
    messages = update_user_tasks(username)
    for msg in messages:
        flash(msg)

    # ترتيب المستخدمين حسب الرصيد
    users = load_users()
    users = [u for u in users if u.get("username", "").strip() != "gatapro901"]
    users.sort(key=lambda x: float(x.get("balance", 0)), reverse=True)

    # جمع عدد الأجهزة النشطة للمستخدم
    items = load_items()
    user_items = [i for i in items if i.get("owner") == username]
    active_count = len([i for i in user_items if i.get("active")])

    return render_template(
        "dashboard.html",
        user=user,
        users=users,
        active_count=active_count
    )

# ---------- Mining control (global per-user) ----------
@app.route('/start_mining')
def start_mining():
    if 'user' not in session:
        return jsonify({"ok": False, "msg": "not logged"}), 401

    username = session['user']
    if username == "gatapro901":
        return jsonify({"ok": False, "msg": "admin cannot mine"})

    users = load_users()
    user = next((u for u in users if u.get("username") == username), None)
    if not user:
        return jsonify({"ok": False, "msg": "user not found"})

    items = load_items()
    now = int(time.time())

    # جلب الأجهزة المملوكة للمستخدم
    user_items = [i for i in items if i.get("owner") == username]

    if not user_items:
        return jsonify({"ok": False, "msg": "ليس لديك أي جهاز — اشترِ جهاز أولاً"})

    # تحقق إن على الأقل جهاز واحد شغّال (power_on=True)
    powered = [i for i in user_items if i.get("power_on", False)]
    if not powered:
        return jsonify({"ok": False, "msg": "لا يوجد جهاز شغّال — شغّل جهاز من صفحة أجهزتي أولاً"})

    # شغّل التعدين لجميع الأجهزة المفعّلة
    changed = False
    for i in powered:
        if not i.get("active", False):
            i["active"] = True
            i["last_tick"] = now
            changed = True

    if changed:
        save_items(items)

    # تحديث حالة التعدين للمستخدم
    user["mining"] = True
    update_user(user)

    return jsonify({"ok": True, "msg": "تم بدء التعدين", "mining": True})

@app.route('/stop_mining')
def stop_mining():
    if 'user' not in session:
        return jsonify({"ok": False}), 401
    username = session['user']
    users = load_users()
    user = next((u for u in users if u.get("username")==username), None)
    if not user:
        return jsonify({"ok": False}), 404

    items = load_items()
    changed = False
    for i in items:
        if i.get("owner")==username and i.get("active", False):
            i["active"] = False
            i["last_tick"] = None
            changed = True
    if changed:
        save_items(items)

    user["mining"] = False
    update_user(user)

    return jsonify({"ok": True, "msg": "تم إيقاف التعدين", "mining": False})

# ---------- Mining tick (called by client JS loop while mining on) ----------
@app.route('/mining_tick')
def mining_tick():
    if 'user' not in session:
        return jsonify({"ok": False, "msg": "not logged"})
    username = session['user']
    if username == "gatapro901":
        return jsonify({"ok": False, "msg": "admin cannot mine"})

    users = load_users()
    user = next((u for u in users if u.get("username")==username), None)
    if not user:
        return jsonify({"ok": False, "msg": "user not found"})

    # لو المستخدم مش مُفعّل له تعدين، رجّع رسالة
    if not user.get("mining", False):
        return jsonify({"ok": False, "msg": "mining not started"})

    items = load_items()
    now = int(time.time())
    total_sats_added = 0
    changed = False

    for i in items:
        if i.get("owner") != username:
            continue
        # فقط الأجهزة التي تم تفعيل التعدين لها (active=True)
        if not i.get("active", False):
            continue

        interval = int(i.get("interval", 30))
        last_tick = i.get("last_tick")
        if last_tick is None:
            i["last_tick"] = now
            changed = True
            continue

        elapsed = now - int(last_tick)
        if elapsed < interval:
            continue

        cycles = elapsed // interval
        if cycles <= 0:
            continue

        sat_per_cycle = int(i.get("sat_per_cycle", 0))
        sats_gain = cycles * sat_per_cycle
        total_sats_added += sats_gain

        # تقدّم آخر تِك
        i["last_tick"] = int(last_tick) + cycles * interval
        changed = True

    if changed:
        save_items(items)

    if total_sats_added > 0:
        btc_gain = total_sats_added / 100_000_000.0
        user['balance'] = float(user.get('balance', 0)) + btc_gain
        xp_gain = (total_sats_added // 6) * 20
        user['xp'] = int(user.get('xp', 0)) + xp_gain
        user['rank'] = calculate_rank(user['xp'])
        save_users(users)

    return jsonify({
        "ok": True,
        "balance": round(float(user.get('balance', 0)), 8),
        "xp": user.get('xp', 0),
        "rank": user.get('rank', "مبتدأ"),
        "sats_added": total_sats_added
    })
    
# ---------- Withdraw ----------
@app.route("/withdraw")
def withdraw():
    if 'user' not in session:
        return jsonify({"balance":0.0,"xp":0,"rank":"مبتدأ"})
    username = session['user']
    if username == "gatapro901":
        return jsonify({"balance":0.0,"xp":0,"rank":"مبتدأ"})
    user = find_user(username)
    if not user:
        return jsonify({"balance":0.0,"xp":0,"rank":"مبتدأ"})
    user['balance'] = 0.0
    user['xp'] = 0
    user['rank'] = "مبتدأ"
    update_user(user)
    return jsonify({"balance":user['balance'],"xp":user['xp'],"rank":user['rank']})

# ---------- Settings ----------
@app.route("/settings", methods=["GET","POST"])
def settings():
    if 'user' not in session:
        return redirect(url_for("login"))
    username = session['user']
    user = find_user(username)
    if username=="gatapro901":
        admin_obj = {"username":"gatapro901","theme":"light"}
        return render_template("settings.html", user=admin_obj)
    if not user:
        session.pop('user',None)
        return redirect(url_for("login"))

    if request.method=="POST":
        new_username = request.form.get('username',user['username']).strip()
        new_password = request.form.get('password',user.get('password','')).strip()
        new_currency = request.form.get('currency',user.get('currency','bitcoin'))
        new_theme = request.form.get('theme',user.get('theme','light'))

        if new_username != user['username'] and find_user(new_username):
            return render_template("settings.html", user=user, msg="هذا الاسم مستخدم بالفعل")

        user['username']=new_username
        user['password']=new_password
        user['currency']=new_currency
        user['theme']=new_theme
        update_user(user)
        session['user']=new_username
        return redirect(url_for("dashboard"))

    return render_template("settings.html", user=user)

# ---------- Delete Account ----------
@app.route("/delete_my_account", methods=["POST"])
def delete_my_account():
    if 'user' not in session:
        return redirect(url_for("login"))
    username = session['user']
    if username=="gatapro901":
        return redirect(url_for("dashboard"))
    delete_user_by_name(username)
    session.pop('user',None)
    return redirect(url_for("login"))

# ---------- Store ----------
@app.route("/store")
def store():
    if 'user' not in session:
        return redirect(url_for("login"))
    # send store catalog to template
    return render_template("store.html", items=STORE_ITEMS)

@app.route("/buy_item/<int:item_id>")
def buy_item(item_id):
    if 'user' not in session:
        return redirect(url_for("login"))
    username = session['user']
    user = find_user(username)
    if not user:
        return redirect(url_for("login"))

    store_item = next((i for i in STORE_ITEMS if i["id"]==item_id),None)
    if store_item is None:
        return redirect(url_for("store"))

    # التحقق من الرصيد
    if user.get("balance",0) < store_item["price"]:
        return render_template("store.html", items=STORE_ITEMS, msg="رصيد غير كافٍ")
    
    # خصم السعر
    user["balance"] -= store_item["price"]
    update_user(user)
    
    # إضافة الجهاز للمستخدم
    add_item_to_user(username, store_item)
    
    return redirect(url_for("items"))
# ---------- User Items ----------
@app.route("/items")
def items():
    if "user" not in session:
        return redirect(url_for("login"))

    username = session["user"]
    user_items = get_user_items(username)

    return render_template("items.html", items=user_items)

@app.route("/toggle_item/<item_id>")
def toggle_item(item_id):
    if 'user' not in session:
        return jsonify({"ok":False})
    username = session['user']
    items = load_items()
    new_active = False
    msg = "الجهاز غير موجود"
    for i in items:
        if i.get("id")==item_id and i.get("owner")==username:
            new_active = not bool(i.get("active", False))
            i["active"] = new_active
            if new_active:
                i["last_tick"] = int(time.time())
                msg = "تم تشغيل الجهاز وبدء التعدين"
            else:
                i["last_tick"] = None
                msg = "تم إيقاف الجهاز وإيقاف التعدين"
            break
    save_items(items)
    user = find_user(username)
    return jsonify({"ok":True, "active": new_active, "message": msg})

@app.route("/device_tick/<item_id>")
def device_tick(item_id):
    if 'user' not in session:
        return jsonify({"ok":False})

    username = session['user']
    items = load_items()
    users = load_users()

    user = None
    for u in users:
        if u["username"] == username:
            user = u
            break

    if not user:
        return jsonify({"ok":False, "msg":"user not found"})

    for i in items:
        if i.get("id") == item_id and i.get("owner") == username and i.get("active", False):
            user["balance"] += float(i["sat_per_cycle"]) / 100_000_000
            break

    save_users(users)
    return jsonify({"ok":True, "balance": user["balance"]})

# ---------- Admin (basic) ----------
@app.route("/admin")
def admin():
    if 'user' not in session or session['user']!="gatapro901":
        return redirect(url_for("login"))
    users = load_users()
    return render_template("admin.html", users=users)

# ---------- Admin Advanced (new route) ----------
@app.route("/admin_advanced")
def admin_advanced():
    if 'user' not in session or session['user']!="gatapro901":
        return redirect(url_for("login"))
    users = load_users()
    # sort by balance desc
    users.sort(key=lambda x: float(x.get("balance",0)), reverse=True)
    items = load_items()
    return render_template("admin_advanced.html", users=users, items=items)

# ---------- Admin Actions ----------
@app.route("/admin_block/<username>")
def admin_block(username):
    if 'user' not in session or session['user']!="gatapro901":
        return redirect(url_for("login"))
    user = find_user(username)
    if user:
        user['blocked'] = True
        update_user(user)
    return redirect(url_for("admin"))

@app.route("/admin_unblock/<username>")
def admin_unblock(username):
    if 'user' not in session or session['user']!="gatapro901":
        return redirect(url_for("login"))
    user = find_user(username)
    if user:
        user['blocked'] = False
        update_user(user)
    return redirect(url_for("admin"))

@app.route("/admin_delete/<username>")
def admin_delete(username):
    if 'user' not in session or session['user']!="gatapro901":
        return redirect(url_for("login"))
    delete_user_by_name(username)
    return redirect(url_for("admin"))

@app.route("/admin_update/<username>", methods=["POST"])
def admin_update(username):
    if 'user' not in session or session['user'] != "gatapro901":
        return redirect(url_for("login"))
    user = find_user(username)
    if not user:
        return redirect(url_for("admin"))
    try:
        new_balance = float(request.form.get("balance", user.get("balance",0)))
        new_xp = int(request.form.get("xp", user.get("xp",0)))
        new_rank = request.form.get("rank", user.get("rank","مبتدأ"))
        user["balance"] = new_balance
        user["xp"] = new_xp
        user["rank"] = new_rank
        update_user(user)
    except:
        pass
    return redirect(url_for("admin_advanced"))

# ---------- Backwards-compatible simple routes used by some templates ----------
@app.route("/block_user/<username>")
def block_user(username):
    return redirect(url_for("admin_block", username=username))

@app.route("/unblock_user/<username>")
def unblock_user(username):
    return redirect(url_for("admin_unblock", username=username))

@app.route("/delete_user/<username>")
def delete_user(username):
    return redirect(url_for("admin_delete", username=username))

# ---------- Buy Pages Routes ----------
@app.route("/buy_page/1")
def buy_page_1():
    return render_template("buy_1.html")

@app.route("/buy_page/2")
def buy_page_2():
    return render_template("buy_2.html")

@app.route("/buy_page/3")
def buy_page_3():
    return render_template("buy_3.html")

@app.route("/buy_page/4")
def buy_page_4():
    return render_template("buy_4.html")

@app.route("/buy_page/5")
def buy_page_5():
    return render_template("buy_5.html")

@app.route("/buy_page/6")
def buy_page_6():
    return render_template("buy_6.html")

@app.route("/buy_page/7")
def buy_page_7():
    return render_template("buy_7.html")

@app.route("/buy_page/8")
def buy_page_8():
    return render_template("buy_8.html")

# ==================== ROUTES الجديدة للأجهزة ====================

#تشغيل / إيقاف تشغيل الجهاز
@app.route('/toggle_power/<item_id>')
def toggle_power(item_id):
    if 'user' not in session:
        return jsonify({"error": "Unauthorized"}), 401
    username = session['user']

    items = load_items()
    item = next((i for i in items if str(i.get("id")) == str(item_id) and i.get("owner") == username), None)
    if not item:
        return jsonify({"error": "Item not found or not yours"}), 404

    # قلب حالة التشغيل
    item["power_on"] = not bool(item.get("power_on", False))

    # لو طفيت الجهاز نضمن إنه موقّف من التعدين كمان
    if not item["power_on"]:
        item["active"] = False
        item["last_tick"] = None

    save_items(items)

    if item["power_on"]:
        return jsonify({"message": f"تم تشغيل الجهاز {item.get('name')}", "active": True})
    else:
        return jsonify({"message": f"تم إيقاف تشغيل الجهاز {item.get('name')}", "active": False})
        
# تبديل حالة التعدين على جهاز محدد (بتفعيل الجهاز لازم)
@app.route('/toggle_mining/<item_id>')
def toggle_mining(item_id):
    if 'user' not in session:
        return jsonify({"error":"Unauthorized"}), 401
    username = session['user']

    items = load_items()
    item = next((i for i in items if str(i.get("id")) == str(item_id) and i.get("owner") == username), None)
    if not item:
        return jsonify({"error":"Item not found or not yours"}), 404

    if not item.get("power_on", False):
        return jsonify({"message":"شغل الجهاز الأول قبل التعدين", "mining": False})

    item["active"] = not bool(item.get("active", False))
    if item["active"]:
        item["last_tick"] = int(time.time())
    else:
        item["last_tick"] = None
    save_items(items)

    return jsonify({"message": f"{'تم بدء' if item['active'] else 'تم إيقاف'} التعدين على جهاز {item.get('name')}", "mining": item["active"]})

@app.route('/tasks')
def tasks_page():
    if 'user' not in session:
        return redirect(url_for('login'))

    username = session['user'].strip().lower()  # توحيد الاسم
    tasks = get_user_tasks(username)  # جلب المهام الخاصة بالمستخدم

    # التأكد من صيغة المكافأة للساتوشي
    for t in tasks:
        if t['type'] == 'btc':
            t['reward'] = "{:.8f}".format(float(t.get('reward', 0)))
        else:
            t['reward'] = int(t.get('reward', 0))

    return render_template("tasks.html", tasks=tasks)

@app.route('/complete_task/<condition>')
def complete_task(condition):
    if 'user' not in session:
        return jsonify({"ok": False, "msg": "غير مسجل دخول"}), 401

    username = session['user'].strip().lower()

    # جلب المستخدم
    users = load_users()
    user = next((u for u in users if u.get("username","").strip().lower() == username), None)
    if not user:
        return jsonify({"ok": False, "msg": "مستخدم غير موجود"})

    # جلب المهام الخاصة بالمستخدم
    tasks_data = load_tasks()
    if username not in tasks_data:
        tasks_data[username] = [dict(t) for t in DEFAULT_TASKS]
        save_tasks(tasks_data)

    user_tasks = tasks_data[username]
    task = next((t for t in user_tasks if t.get("condition") == condition), None)
    if not task:
        return jsonify({"ok": False, "msg": "المهمة غير موجودة"})

    if task.get("completed", False):
        return jsonify({"ok": False, "msg": "المهمة مكتملة مسبقًا"})

    # ===== تحقق من شرط المهمة =====
    condition_ok = False
    msg_fail = "لسه ماحققتش شرط المهمة 🔒"

    if condition == "first_login":
        # أول تسجيل دخول يتحقق تلقائيًا
        condition_ok = True

    if condition.startswith("buy_"):
        try:
            needed = int(condition.replace("buy_", "").replace("_items",""))
        except:
            needed = 0
        user_items = [i for i in load_items() if str(i.get("owner","")).strip().lower() == username]
        if len(user_items) >= needed:
            condition_ok = True
        else:
            msg_fail = f"يجب شراء {needed} أجهزة أولًا"

    if condition == "login_7_days":
        if int(user.get("login_streak",0)) >= 7:
            condition_ok = True
        else:
            msg_fail = "يجب تسجيل الدخول 7 أيام متتالية"

    if condition == "login_30_days":
        if int(user.get("login_streak",0)) >= 30:
            condition_ok = True
        else:
            msg_fail = "يجب تسجيل الدخول 30 يومًا متتالية"

    if not condition_ok:
        return jsonify({"ok": False, "msg": msg_fail})

    # ===== إتمام المهمة =====
    task["completed"] = True

    if task.get("type") == "btc":
        reward = float(task.get("reward",0))
        user["balance"] = float(user.get("balance",0)) + reward
        user["balance"] = float(f"{user['balance']:.8f}")  # ساتوشي

    elif task.get("type") == "xp":
        reward = int(task.get("reward",0))
        user["xp"] = int(user.get("xp",0)) + reward
        user["rank"] = calculate_rank(user["xp"])

    # حفظ البيانات
    tasks_data[username] = user_tasks
    save_tasks(tasks_data)
    save_users(users)

    return jsonify({"ok": True, "msg": f"تم إكمال المهمة: {task.get('title','(بدون عنوان)')} 🎉"})
            
@app.route('/pending_tasks_count')
def pending_tasks_count():
    if 'user' not in session:
        return jsonify({"ok": False, "msg": "غير مسجل دخول", "count": 0})

    username = session['user']
    tasks = load_tasks()  # افترض إن عندك دالة load_tasks() بترجع كل المهام
    count = 0

    for task in tasks:
        # كل مهمة فيها حقل completed لكل مستخدم (مثلاً task["completed_by"] = ["user1", "user2"])
        completed_users = task.get("completed_by", [])
        if username not in completed_users:
            count += 1

    return jsonify({"ok": True, "count": count})

@app.route('/tasks_status')
def tasks_status():
    if 'user' not in session:
        return jsonify({"ok": False})

    username = session['user'].strip().lower()

    # جلب بيانات المهام
    tasks_data = load_tasks()
    if username not in tasks_data or not tasks_data[username]:
        # إنشاء نسخة جديدة للمستخدم
        tasks_data[username] = [dict(t, completed=False) for t in DEFAULT_TASKS]
        save_tasks(tasks_data)

    user_tasks = tasks_data[username]

    # التأكد من وجود مفتاح "completed" لكل مهمة
    for t in user_tasks:
        if "completed" not in t:
            t["completed"] = False

    return jsonify({"ok": True, "tasks": user_tasks})
    
    # أرشادات للمستخدم الجديد
    show_guide = all(not t['completed'] for t in user_tasks[:1])  # لو أول مهمة مش مكتملة
    return render_template("tasks.html", tasks=user_tasks, show_guide=show_guide)

# =======================================================================

# ---------- Run ----------
if __name__ == "__main__":
    # بياخد البورت من السيرفر، ولو ملقاش بياخد 5000 تلقائي
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
