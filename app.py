from flask import Flask, request, jsonify, session, redirect, render_template_string
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from datetime import datetime
import os, re, base64, secrets, sqlite3

load_dotenv()

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("FLASK_SECRET_KEY", "dev-secret-change-me")
app.config["SESSION_COOKIE_SECURE"] = os.getenv("COOKIE_SECURE", "0") == "1"
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///ninjaboy.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

UPLOAD_DIR = os.path.join(os.getcwd(), "private_uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Bot(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    telegram_bot_id = db.Column(db.BigInteger, unique=True, nullable=False)
    username = db.Column(db.String(120), nullable=False)
    display_name = db.Column(db.String(200), nullable=False)
    encrypted_token = db.Column(db.Text, nullable=False)
    profile_image_ref = db.Column(db.String(255), nullable=True)
    status = db.Column(db.String(32), default="UNKNOWN")
    worker_assignment = db.Column(db.String(120), default="default")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class ScriptFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    bot_id = db.Column(db.Integer, db.ForeignKey("bot.id"), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    internal_storage_key = db.Column(db.String(255), nullable=False)
    file_size = db.Column(db.Integer, default=0)
    uploaded_at = db.Column(db.DateTime, default=datetime.utcnow)

class Job(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    bot_id = db.Column(db.Integer, db.ForeignKey("bot.id"), nullable=False)
    worker_id = db.Column(db.String(120), default="default")
    process_state = db.Column(db.String(32), default="STOPPED")
    start_timestamp = db.Column(db.DateTime, nullable=True)
    stop_timestamp = db.Column(db.DateTime, nullable=True)
    exit_code = db.Column(db.Integer, nullable=True)
    logs = db.Column(db.Text, default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class AuditEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    admin_id = db.Column(db.Integer, db.ForeignKey("admin.id"), nullable=False)
    action = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    metadata = db.Column(db.Text, default="{}")

with app.app_context():
    db.create_all()
    if not Admin.query.filter_by(username=os.getenv("PANEL_USERNAME", "admin")).first():
        admin_user = os.getenv("PANEL_USERNAME", "admin")
        admin_pass = os.getenv("PANEL_PASSWORD", "AdminPass123!")
        db.session.add(Admin(username=admin_user, password_hash=generate_password_hash(admin_pass)))
        db.session.commit()


def get_fernet():
    secret = os.getenv("TOKEN_ENCRYPTION_KEY")
    if not secret:
        secret = "f8k6c1uWnNw0Y9kA5d1i4c0w8x0F4Jq0"
    if len(secret) < 32:
        secret = secret.ljust(32, "0")
    return Fernet(base64.urlsafe_b64encode(secret.encode()[:32].ljust(32, b"0")))


def encrypt_token(value):
    return get_fernet().encrypt(value.encode()).decode()


def decrypt_token(value):
    return get_fernet().decrypt(value.encode()).decode()


def redact(value):
    if not value:
        return ""
    v = str(value)
    for key in ["TOKEN", "PASSWORD", "SECRET", "KEY"]:
        if key in v.upper():
            return "[REDACTED]"
    return v


def telegram_api(method, token, params=None, timeout=10):
    import requests
    url = f"https://api.telegram.org/bot{token}/{method}"
    response = requests.get(url, params=params or {}, timeout=timeout)
    try:
        data = response.json()
    except ValueError:
        raise RuntimeError("Telegram API returned invalid response.")
    if not data.get("ok"):
        raise ValueError(data.get("description", "Telegram API rejected the request."))
    return data.get("result")


def get_bot_profile(token):
    me = telegram_api("getMe", token)
    profile = {
        "id": me.get("id"),
        "is_bot": me.get("is_bot", False),
        "first_name": me.get("first_name", ""),
        "username": me.get("username", ""),
        "can_join_groups": me.get("can_join_groups", False),
        "can_read_all_group_messages": me.get("can_read_all_group_messages", False),
        "supports_inline_queries": me.get("supports_inline_queries", False),
    }
    try:
        photos = telegram_api("getUserProfilePhotos", token, {"user_id": profile["id"]})
        photo = None
        for batch in photos.get("photos", []):
            for item in batch:
                if photo is None or item.get("file_size", 0) > photo.get("file_size", 0):
                    photo = item
        if photo:
            file_info = telegram_api("getFile", token, {"file_id": photo["file_id"]})
            file_path = file_info.get("file_path")
            if file_path:
                profile["profile_image_url"] = f"https://api.telegram.org/file/bot{token}/{file_path}"
            else:
                profile["profile_image_url"] = None
        else:
            profile["profile_image_url"] = None
    except Exception:
        profile["profile_image_url"] = None
    return profile


def require_login():
    if "admin_id" not in session:
        return False
    return True


@app.route("/healthz")
def healthz():
    return jsonify({"status": "ok"})


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        admin = Admin.query.filter_by(username=username).first()
        if admin and check_password_hash(admin.password_hash, password):
            session.clear()
            session["admin_id"] = admin.id
            session["admin_username"] = admin.username
            return redirect("/dashboard")
        return "Invalid login", 401

    return render_template_string('''
    <html>
    <head><title>🐉 ΝᏆΝᎫᎪ ᏴϴᎽ 🐲 | Login</title>
    <style>
        body { margin:0; background:radial-gradient(circle at top,#0d1713,#060a08 58%); color:#eafef0; font-family:Arial,sans-serif; }
        .wrap { min-height:100vh; display:grid; place-items:center; }
        .card { background:linear-gradient(180deg,#111915,#0b120f); border:1px solid rgba(96,255,180,0.35); border-radius:20px; padding:30px; width:min(420px,90vw); box-shadow:0 0 24px rgba(53,255,152,0.14); }
        .brand { font-size:2.2rem; letter-spacing:0.14em; color:#7afec0; font-weight:800; text-shadow:0 0 18px rgba(98,255,178,0.3); }
        .tag { color:#9ad9b7; letter-spacing:0.2em; font-size:0.72rem; text-transform:uppercase; margin-bottom:18px; }
        h1 { margin-top:0; color:#76ffc2; }
        input { width:100%; box-sizing:border-box; margin-top:8px; margin-bottom:12px; padding:12px 14px; border-radius:10px; border:1px solid rgba(118,255,194,0.25); background:#0b100d; color:white; }
        button { width:100%; padding:13px; border:none; border-radius:12px; background:linear-gradient(135deg,#34f3a6,#1bbf7b); color:#07140d; font-weight:900; box-shadow:0 0 18px rgba(51,255,158,0.35); }
    </style>
    </head>
    <body>
    <div class='wrap'>
      <div class='card'>
        <div class='brand'>🐉 ΝᏆΝᎫᎪ ᏴϴᎽ 🐲</div>
        <div class='tag'>BOT HOSTING PANEL</div>
        <form method='POST'>
          <label>Username<input name='username' required></label>
          <label>Password<input name='password' type='password' required></label>
          <button type='submit'>Access Panel</button>
        </form>
      </div>
    </div>
    </body>
    </html>
    ''')


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


@app.route("/")
def index():
    return redirect("/dashboard")


@app.route("/dashboard")
def dashboard():
    if not require_login():
        return redirect("/login")

    bots = Bot.query.order_by(Bot.created_at.desc()).all()
    total = len(bots)
    running = sum(1 for b in bots if b.status.upper() == "RUNNING")
    stopped = sum(1 for b in bots if b.status.upper() == "STOPPED")
    failed = sum(1 for b in bots if b.status.upper() == "FAILED")
    script_count = ScriptFile.query.count()
    recent = bots[:5]

    return render_template_string('''
    <html>
    <head><title>🐉 ΝᏆΝᎫᎪ ᏴϴᎽ 🐲 | Dashboard</title>
    <style>
      body { margin:0; background:radial-gradient(circle at top,#0d1713,#060a08 58%); color:#eafef0; font-family:Arial,sans-serif; }
      .layout { display:flex; min-height:100vh; }
      .sidebar { width:230px; background:#0f1713; padding:24px; border-right:1px solid rgba(90,255,175,0.2); }
      .brand { font-weight:900; color:#7afec0; letter-spacing:0.12em; font-size:1.12rem; text-shadow:0 0 16px rgba(98,255,178,0.3); }
      .nav a { display:block; color:#eafef0; text-decoration:none; padding:11px 12px; margin:8px 0; border-radius:10px; background:rgba(255,255,255,0.02); }
      .nav a:hover { border:1px solid rgba(90,255,175,0.25); }
      .content { flex:1; padding:28px; }
      .topbar { display:flex; justify-content:space-between; align-items:center; }
      .status { padding:8px 12px; border-radius:999px; background:rgba(51,255,158,0.08); border:1px solid rgba(51,255,158,0.35); color:#8dffbd; }
      .cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:16px; margin-top:18px; }
      .card { background:linear-gradient(180deg,#121b18,#0c110f); border:1px solid rgba(85,255,170,0.18); border-radius:16px; padding:18px; }
      .big { font-size:2.3rem; font-weight:bold; }
      .actions { display:flex; flex-wrap:wrap; gap:12px; margin:22px 0; }
      .btn { padding:11px 16px; border-radius:12px; border:1px solid rgba(90,255,175,0.25); text-decoration:none; color:#07140d; background:linear-gradient(135deg,#39f7aa,#1ecb7e); font-weight:bold; }
      .btn.alt { background:#111915; color:#eafef0; }
      table { width:100%; border-collapse:collapse; margin-top:18px; }
      th, td { text-align:left; padding:12px; border-bottom:1px solid rgba(255,255,255,0.08); }
    </style>
    </head>
    <body>
    <div class='layout'>
      <aside class='sidebar'>
        <div class='brand'>🐉 ΝᏆΝᎫᎪ ᏴϴᎽ 🐲</div>
        <div style='margin:12px 0 18px; color:#9bc7ae; letter-spacing:0.14em; font-size:0.7rem; text-transform:uppercase;'>BOT HOSTING</div>
        <nav class='nav'>
          <a href='/dashboard'>Dashboard</a>
          <a href='/bot-profile'>Bot Profile</a>
          <a href='/bots'>Manage Bots</a>
          <a href='/upload-script'>Upload Script</a>
          <a href='/logs'>Logs</a>
          <a href='/logout'>Logout</a>
        </nav>
      </aside>
      <main class='content'>
        <div class='topbar'>
          <div>
            <div style='color:#9bc7ae; letter-spacing:0.12em; text-transform:uppercase; font-size:0.72rem;'>Administrator</div>
            <h2>{{ username }}</h2>
          </div>
          <div class='status'>System Status: ONLINE</div>
        </div>

        <div class='cards'>
          <div class='card'><div>Total Registered Bots</div><div class='big'>{{ total }}</div></div>
          <div class='card'><div>Running Bots</div><div class='big'>{{ running }}</div></div>
          <div class='card'><div>Stopped Bots</div><div class='big'>{{ stopped }}</div></div>
          <div class='card'><div>Failed Bots</div><div class='big'>{{ failed }}</div></div>
          <div class='card'><div>Total Uploaded Scripts</div><div class='big'>{{ script_count }}</div></div>
        </div>

        <div class='actions'>
          <a class='btn' href='/bot-profile'>Add Telegram Bot</a>
          <a class='btn alt' href='/bot-profile'>Read Bot Profile</a>
          <a class='btn alt' href='/upload-script'>Upload Python Script</a>
          <a class='btn alt' href='/logs'>View Bot Logs</a>
          <a class='btn alt' href='/bots'>Manage Bots</a>
        </div>

        <div class='card'>
          <h3>Recent Bot Activity</h3>
          <table>
            <tr><th>Bot</th><th>Username</th><th>Status</th></tr>
            {% for bot in recent %}
            <tr>
              <td>{{ bot.display_name }}</td>
              <td>@{{ bot.username }}</td>
              <td>{{ bot.status }}</td>
            </tr>
            {% endfor %}
          </table>
        </div>
      </main>
    </div>
    </body>
    </html>
    ''', username=session.get("admin_username"), total=total, running=running, stopped=stopped, failed=failed, script_count=script_count, recent=recent)


@app.route("/bot-profile", methods=["GET", "POST"])
def bot_profile():
    if not require_login():
        return redirect("/login")

    if request.method == "POST":
        token = (request.form.get("token") or "").strip()
        if not token:
            return "Token is required.", 400
        try:
            profile = get_bot_profile(token)
            session["pending_bot"] = profile
            session["pending_token"] = token
            return render_template_string('''
            <html>
            <head><title>Telegram Bot Profile</title>
            <style>body{margin:0;background:radial-gradient(circle at top,#0d1713,#060a08 58%);color:#ebfff4;font-family:Arial,sans-serif;} .wrap{padding:28px;} .card{background:linear-gradient(180deg,#111915,#0b120f);border:1px solid rgba(85,255,170,0.22);border-radius:18px;padding:20px;max-width:700px;margin:auto;} img{width:90px;height:90px;border-radius:50%;object-fit:cover;background:#0b100d;border:1px solid rgba(85,255,170,0.22);} .name{font-size:2rem;font-weight:bold;} .meta{color:#c4d7cb;} .row{display:flex;gap:18px;align-items:center;} .btn{padding:10px 14px;border-radius:10px;background:linear-gradient(135deg,#39f7aa,#1ecb7e);color:#07140d;text-decoration:none;font-weight:bold;display:inline-block;margin-top:12px;} form{margin-top:18px;} input, textarea, select{width:100%;box-sizing:border-box;background:#0b100d;color:white;border:1px solid rgba(85,255,170,0.18);padding:12px;border-radius:10px;margin:8px 0;} button{padding:12px 18px;border:none;border-radius:10px;background:#2bf4a7;color:#06120d;font-weight:bold;}</style></head>
            <body>
            <div class='wrap'>
              <div class='card'>
                <div class='row'>
                  {% if bot.profile_image_url %}
                    <img src='{{ bot.profile_image_url }}'>
                  {% else %}
                    <img src='https://ui-avatars.com/api/?name={{ bot.first_name|urlencode }}&background=0d1a14&color=7dffc9&size=128'>
                  {% endif %}
                  <div>
                    <div class='name'>{{ bot.first_name or bot.username }}</div>
                    <div class='meta'>@{{ bot.username }}</div>
                    <div class='meta'>Telegram ID: {{ bot.id }}</div>
                  </div>
                </div>
                <div class='meta'>Verification: OK</div>
                <form action='/bot-register' method='POST'>
                  <input name='display_name' value='{{ bot.first_name or bot.username }}' required>
                  <input name='username' value='{{ bot.username }}' required>
                  <textarea name='description' placeholder='Optional description'></textarea>
                  <input name='worker_assignment' value='default'>
                  <select name='status'>
                    <option>STOPPED</option>
                    <option>RUNNING</option>
                    <option>FAILED</option>
                    <option>UNKNOWN</option>
                  </select>
                  <button type='submit'>Register this bot</button>
                </form>
              </div>
            </div>
            </body>
            </html>
            ''', bot=profile)
        except Exception as exc:
            return f"Invalid Telegram token or API error: {redact(str(exc))}", 400

    return render_template_string('''
    <html><head><title>🐉 ΝᏆΝᎫᎪ ᏴϴᎽ 🐲 | Bot Profile</title><style>body{margin:0;background:radial-gradient(circle at top,#0d1713,#060a08 58%);color:#ecffef;font-family:Arial,sans-serif;} .wrap{min-height:100vh;display:grid;place-items:center;} .card{background:linear-gradient(180deg,#111915,#0b120f);border:1px solid rgba(85,255,170,0.22);padding:24px;border-radius:18px;width:min(520px,90vw);box-shadow:0 0 24px rgba(53,255,152,0.1);} .brand{font-size:2rem;font-weight:800;color:#7afec0;letter-spacing:0.12em;text-transform:uppercase;} input,button{width:100%;box-sizing:border-box;padding:12px;border-radius:10px;border:1px solid rgba(85,255,170,0.2);margin-top:10px;background:#0c120f;color:white;} button{background:linear-gradient(135deg,#35f8ab,#1bcf7e);color:#07140d;font-weight:bold;border:none;}</style></head><body><div class='wrap'><div class='card'><div class='brand'>🐉 ΝᏆΝᎫᎪ ᏴϴᎽ 🐲</div><h2 style='margin-top:8px;'>Bot Profile Reader</h2><form method='POST'><input name='token' placeholder='Paste Telegram bot token' required><button type='submit'>Read Profile</button></form></div></div></body></html>
    ''')


@app.route("/bot-register", methods=["POST"])
def bot_register():
    if not require_login():
        return redirect("/login")

    token = session.get("pending_token")
    profile = session.get("pending_bot")
    if not token or not profile:
        return "No pending Telegram profile data found", 400

    telegram_bot_id = profile.get("id")
    username = (request.form.get("username") or profile.get("username") or "").strip()
    display_name = (request.form.get("display_name") or profile.get("first_name") or username).strip()
    description = (request.form.get("description") or "").strip()
    worker_assignment = (request.form.get("worker_assignment") or "default").strip()
    status = (request.form.get("status") or "STOPPED").strip().upper()

    if not username or not display_name or not telegram_bot_id:
        return "Invalid bot profile data.", 400

    existing = Bot.query.filter_by(telegram_bot_id=telegram_bot_id).first()
    if existing:
        return "This bot is already registered.", 409

    bot = Bot(
        telegram_bot_id=telegram_bot_id,
        username=username,
        display_name=display_name,
        encrypted_token=encrypt_token(token),
        profile_image_ref=profile.get("profile_image_url"),
        status=status,
        worker_assignment=worker_assignment,
    )
    db.session.add(bot)
    db.session.commit()

    admin = Admin.query.get(session["admin_id"])
    db.session.add(AuditEvent(admin_id=admin.id, action="registered_bot", metadata=f'{{"bot_id":{bot.id}, "username":"{username}"}}'))
    db.session.commit()

    session.pop("pending_bot", None)
    session.pop("pending_token", None)
    return redirect("/dashboard")


@app.route("/bots")
def bots():
    if not require_login():
        return redirect("/login")
    bot_list = Bot.query.order_by(Bot.created_at.desc()).all()
    return render_template_string('''
    <html><head><title>Manage Bots</title><style>body{margin:0;background:radial-gradient(circle at top,#0d1713,#060a08 58%);color:#ebfff4;font-family:Arial,sans-serif;} .wrap{padding:24px;} .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:16px;} .card{background:linear-gradient(180deg,#111915,#0b120f);border:1px solid rgba(85,255,170,0.2);padding:18px;border-radius:16px;} .top{display:flex;align-items:center;gap:14px;} img{width:56px;height:56px;border-radius:50%;object-fit:cover;border:1px solid rgba(85,255,170,0.28);} .name{font-weight:bold;font-size:1.2rem;} .meta{color:#c2d7c9; font-size:0.9rem;} .actions a{display:inline-block;margin-right:8px;margin-top:12px;color:#98ffd7;text-decoration:none;} .back{color:#8ef7c0;text-decoration:none;display:inline-block;margin-bottom:18px;} .brand{font-weight:900;color:#7afec0;letter-spacing:0.12em;}</style></head><body><div class='wrap'><div class='brand'>🐉 ΝᏆΝᎫᎪ ᏴϴᎽ 🐲</div><a href='/dashboard' class='back'>← Dashboard</a><div class='grid'>{% for bot in bots %}<div class='card'><div class='top'><img src='{{ bot.profile_image_ref or "https://ui-avatars.com/api/?name=" + bot.display_name + "&background=0d1a14&color=7dffc9&size=128" }}'><div><div class='name'>{{ bot.display_name }}</div><div class='meta'>@{{ bot.username }}</div></div></div><div class='meta'>Bot ID: {{ bot.telegram_bot_id }}</div><div class='meta'>Status: {{ bot.status }}</div><div class='meta'>Worker: {{ bot.worker_assignment }}</div><div class='actions'><a href='/bot/{{ bot.id }}'>View Details</a><a href='/api/bot/{{ bot.id }}/start'>Start</a><a href='/api/bot/{{ bot.id }}/stop'>Stop</a><a href='/api/bot/{{ bot.id }}/restart'>Restart</a></div></div>{% endfor %}</div></div></body></html>
    ''', bots=bot_list)


@app.route("/bot/<int:bot_id>")
def bot_detail(bot_id):
    if not require_login():
        return redirect("/login")
    bot = Bot.query.get_or_404(bot_id)
    return render_template_string('''
    <html><head><title>Bot Details</title><style>body{margin:0;background:radial-gradient(circle at top,#0d1713,#060a08 58%);color:#ebfff4;font-family:Arial,sans-serif;} .card{max-width:700px;margin:30px auto;background:linear-gradient(180deg,#111915,#0b120f);border:1px solid rgba(90,255,175,0.2);padding:20px;border-radius:18px;} img{width:88px;height:88px;border-radius:50%;object-fit:cover;} .label{color:#bfe7d2;} .value{font-weight:bold;}</style></head><body><div class='card'><img src='{{ bot.profile_image_ref or "https://ui-avatars.com/api/?name=" + bot.display_name + "&background=0d1a14&color=7dffc9&size=128" }}'><h2>{{ bot.display_name }}</h2><div class='label'>Username</div><div class='value'>@{{ bot.username }}</div><div class='label'>Telegram ID</div><div class='value'>{{ bot.telegram_bot_id }}</div><div class='label'>Status</div><div class='value'>{{ bot.status }}</div><div class='label'>Worker Assignment</div><div class='value'>{{ bot.worker_assignment }}</div></div></body></html>
    ''', bot=bot)


@app.route("/upload-script", methods=["GET", "POST"])
def upload_script():
    if not require_login():
        return redirect("/login")

    if request.method == "POST":
        bot_id = request.form.get("bot_id")
        file = request.files.get("script")
        if not bot_id or not file:
            return "Bot and script are required.", 400
        if not file.filename.lower().endswith(".py"):
            return "Only .py files permitted.", 400

        filename = secure_filename(file.filename)
        if not filename or filename.startswith('.') or '/' in filename or '\\' in filename or '..' in filename:
            return "Invalid filename.", 400

        bot = Bot.query.get(int(bot_id))
        if not bot:
            return "Bot not found.", 400

        internal_name = f"{secrets.token_hex(16)}_{filename}"
        full_path = os.path.join(UPLOAD_DIR, internal_name)
        file.save(full_path)

        row = ScriptFile(
            bot_id=bot.id,
            original_filename=filename,
            internal_storage_key=internal_name,
            file_size=os.path.getsize(full_path),
        )
        db.session.add(row)
        db.session.commit()

        admin = Admin.query.get(session["admin_id"])
        db.session.add(AuditEvent(admin_id=admin.id, action="uploaded_script", metadata=f'{{"bot_id":{bot.id}, "filename":"{filename}"}}'))
        db.session.commit()

        return redirect("/logs")

    bots = Bot.query.all()
    return render_template_string('''
    <html><head><title>Upload Python Script</title><style>body{margin:0;background:radial-gradient(circle at top,#0d1713,#060a08 58%);color:#ebfff4;font-family:Arial,sans-serif;} .wrap{display:grid;place-items:center;min-height:100vh;} .card{background:linear-gradient(180deg,#111915,#0b120f);border:1px solid rgba(85,255,170,0.2);padding:24px;border-radius:18px;width:min(620px,90vw);box-shadow:0 0 24px rgba(53,255,152,0.1);} input,select,button{width:100%;box-sizing:border-box;padding:12px;border-radius:10px;margin-top:10px;background:#0c120f;color:white;border:1px solid rgba(85,255,170,0.2);} button{background:linear-gradient(135deg,#35f8ab,#1bcf7e);color:#07140d;font-weight:bold;border:none;}</style></head><body><div class='wrap'><div class='card'><h2>🐉 ΝᏆΝᎫᎪ ᏴϴᎽ 🐲</h2><h3>Upload Python Script</h3><form method='POST' enctype='multipart/form-data'><select name='bot_id'>{% for bot in bots %}<option value='{{ bot.id }}'>{{ bot.display_name }} (@{{ bot.username }})</option>{% endfor %}</select><input type='file' name='script' accept='.py' required><button type='submit'>Upload</button></form></div></div></body></html>
    ''', bots=bots)


@app.route("/logs")
def logs():
    if not require_login():
        return redirect("/login")
    jobs = Job.query.order_by(Job.created_at.desc()).all()
    return render_template_string('''
    <html><head><title>Bot Logs</title><style>body{margin:0;background:radial-gradient(circle at top,#0d1713,#060a08 58%);color:#ebfff4;font-family:Arial,sans-serif;} .wrap{padding:24px;} table{width:100%;border-collapse:collapse;} th,td{padding:12px;border-bottom:1px solid rgba(255,255,255,0.08);text-align:left;} .empty{padding:20px;background:#111915;border:1px solid rgba(85,255,170,0.2);border-radius:16px;} .error{color:#ff9a9a;} .normal{color:#d9fbe3;}</style></head><body><div class='wrap'><h2>🐉 ΝᏆΝᎫᎪ ᏴϴᎽ 🐲 | Logs</h2>{% if not jobs %}<div class='empty'>No logs available yet.</div>{% else %}<table><tr><th>Timestamp</th><th>Bot</th><th>State</th><th>Log</th><th>Exit</th></tr>{% for job in jobs %}<tr><td>{{ job.created_at }}</td><td>{{ job.bot_id }}</td><td>{{ job.process_state }}</td><td class='{% if "error" in job.logs.lower() %}error{% else %}normal{% endif %}'>{{ job.logs[:200] }}</td><td>{{ job.exit_code if job.exit_code is not none else "-" }}</td></tr>{% endfor %}</table>{% endif %}</div></body></html>
    ''', jobs=jobs)


@app.route("/api/bot/<int:bot_id>/start", methods=["POST", "GET"])
def start_bot(bot_id):
    if not require_login():
        return jsonify({"error": "unauthorized"}), 401

    bot = Bot.query.get_or_404(bot_id)
    script = ScriptFile.query.filter_by(bot_id=bot.id).order_by(ScriptFile.uploaded_at.desc()).first()
    if not script:
        return jsonify({"error": "No Python script uploaded for this bot."}), 400

    try:
        import requests
        worker_url = os.getenv("WORKER_API_URL", "http://localhost:9001")
        worker_secret = os.getenv("WORKER_API_SECRET", "dev-worker-secret")
        payload = {"bot_id": bot.id, "script_path": os.path.join(UPLOAD_DIR, script.internal_storage_key), "worker_id": bot.worker_assignment or "default"}
        res = requests.post(f"{worker_url}/jobs/start", json=payload, headers={"X-Worker-Secret": worker_secret}, timeout=12)
        if res.status_code >= 400:
            raise RuntimeError(res.text[:200])
        bot.status = "STARTING"
        db.session.add(bot)
        db.session.commit()
        return jsonify({"status": "ok", "worker_response": res.json()})
    except Exception as exc:
        return jsonify({"error": redact(str(exc))}), 500


@app.route("/api/bot/<int:bot_id>/stop", methods=["POST", "GET"])
def stop_bot(bot_id):
    if not require_login():
        return jsonify({"error": "unauthorized"}), 401

    bot = Bot.query.get_or_404(bot_id)
    try:
        import requests
        worker_url = os.getenv("WORKER_API_URL", "http://localhost:9001")
        worker_secret = os.getenv("WORKER_API_SECRET", "dev-worker-secret")
        res = requests.post(f"{worker_url}/jobs/stop/{bot.id}", headers={"X-Worker-Secret": worker_secret}, timeout=12)
        if res.status_code >= 400:
            raise RuntimeError(res.text[:200])
        bot.status = "STOPPING"
        db.session.add(bot)
        db.session.commit()
        return jsonify({"status": "ok", "worker_response": res.json()})
    except Exception as exc:
        return jsonify({"error": redact(str(exc))}), 500


@app.route("/api/bot/<int:bot_id>/restart", methods=["POST", "GET"])
def restart_bot(bot_id):
    if not require_login():
        return jsonify({"error": "unauthorized"}), 401

    bot = Bot.query.get_or_404(bot_id)
    script = ScriptFile.query.filter_by(bot_id=bot.id).order_by(ScriptFile.uploaded_at.desc()).first()
    if not script:
        return jsonify({"error": "No script available to restart."}), 400

    try:
        import requests
        worker_url = os.getenv("WORKER_API_URL", "http://localhost:9001")
        worker_secret = os.getenv("WORKER_API_SECRET", "dev-worker-secret")
        payload = {"bot_id": bot.id, "script_path": os.path.join(UPLOAD_DIR, script.internal_storage_key), "worker_id": bot.worker_assignment or "default"}
        res = requests.post(f"{worker_url}/jobs/restart", json=payload, headers={"X-Worker-Secret": worker_secret}, timeout=12)
        if res.status_code >= 400:
            raise RuntimeError(res.text[:200])
        bot.status = "STARTING"
        db.session.add(bot)
        db.session.commit()
        return jsonify({"status": "ok", "worker_response": res.json()})
    except Exception as exc:
        return jsonify({"error": redact(str(exc))}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)))
