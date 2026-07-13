"""
LPO VPN - Backend
Flask + SQLite + Zarinpal Payment Gateway

نصب:
    pip install flask flask-sqlalchemy flask-cors pyjwt requests werkzeug

اجرا:
    python app.py
"""

import os
import jwt
import uuid
import requests
import datetime
from functools import wraps
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash

# ---------------------------------------------------------------
# تنظیمات
# ---------------------------------------------------------------
app = Flask(__name__)
CORS(app)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///lpo_vpn.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# ⚠️ این مقدار رو حتماً در نسخهٔ نهایی از متغیرهای محیطی (environment variables) بخون، نه هاردکد در کد
SECRET_KEY = os.environ.get("SECRET_KEY", "CHANGE-THIS-TO-A-RANDOM-SECRET")

# برای اطلاع‌رسانی تلگرامی (مثلاً وقتی کاربر جدید ثبت‌نام می‌کنه)
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
TELEGRAM_ADMIN_CHAT_ID = os.environ.get("TELEGRAM_ADMIN_CHAT_ID", "")

# اطلاعات کارت برای پرداخت کارت‌به‌کارت در بات تلگرام (حتماً در Render تنظیم شود، نه در کد)
CARD_NUMBER = os.environ.get("CARD_NUMBER", "0000-0000-0000-0000")
CARD_HOLDER_NAME = os.environ.get("CARD_HOLDER_NAME", "نام صاحب کارت")

# درگاه پرداخت بانک سامان (سپ) — Terminal ID واقعی رو بعد از دریافت از بانک اینجا بذار
SAMAN_TERMINAL_ID = os.environ.get("SAMAN_TERMINAL_ID", "")
SAMAN_TOKEN_URL = "https://sep.shaparak.ir/onlinepg/onlinepg"
SAMAN_REDIRECT_FORM_URL = "https://sep.shaparak.ir/OnlinePG/SendToken"
SAMAN_VERIFY_URL = "https://sep.shaparak.ir/verifyTxnRandomSessionkey/ipg/VerifyTransaction"
# آدرس سرور خودت (برای بازگشت از بانک) — اگه دامنه‌ت فرق داره، اینو عوض کن
SAMAN_SITE_BASE_URL = os.environ.get("SAMAN_SITE_BASE_URL", "https://lpo-vpn.onrender.com")


def notify_admin_telegram(text):
    """پیام رو به آیدی ادمین در تلگرام می‌فرسته. اگر تنظیم نشده باشه، بی‌سروصدا رد می‌شه."""
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_ADMIN_CHAT_ID:
        return
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        requests.post(url, json={
            "chat_id": TELEGRAM_ADMIN_CHAT_ID,
            "text": text,
        }, timeout=8)
    except Exception:
        pass  # نبود اتصال تلگرام نباید باعث خرابی فرآیند پرداخت بشه

db = SQLAlchemy(app)

# ---------------------------------------------------------------
# مدل‌های دیتابیس
# ---------------------------------------------------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    phone = db.Column(db.String(15), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    subscription_end = db.Column(db.DateTime, nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "phone": self.phone,
            "subscription_end": self.subscription_end.isoformat() if self.subscription_end else None,
            "days_left": self.days_left(),
        }

    def days_left(self):
        if not self.subscription_end:
            return 0
        delta = self.subscription_end - datetime.datetime.utcnow()
        return max(0, delta.days)


class TelegramContact(db.Model):
    """هر کسی که استارت بات رو زده، اینجا ذخیره می‌شه (برای پیام همگانی و لیست مخاطبین)."""
    chat_id = db.Column(db.String(32), primary_key=True)
    username = db.Column(db.String(64), nullable=True)
    first_name = db.Column(db.String(128), nullable=True)
    started_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)


class BotSession(db.Model):
    """پلنی که کاربر توی بات انتخاب کرده، تا موقع ارسال رسید بدونیم برای کدوم پلن بوده."""
    chat_id = db.Column(db.String(32), primary_key=True)
    selected_plan = db.Column(db.Integer, nullable=True)
    last_receipt_message_id = db.Column(db.Integer, nullable=True)


class BotMedia(db.Model):
    """رسانه‌های قابل‌تنظیم بات (مثل ویدیوی آموزش)، بدون نیاز به تغییر کد."""
    key = db.Column(db.String(64), primary_key=True)
    file_id = db.Column(db.String(255), nullable=False)


class SamanOrder(db.Model):
    """سفارش‌های ثبت‌شده برای پرداخت آنلاین از طریق درگاه بانک سامان."""
    res_num = db.Column(db.String(64), primary_key=True)  # شماره سفارش یکتا
    chat_id = db.Column(db.String(32), nullable=False)
    plan_key = db.Column(db.Integer, nullable=False)
    amount_toman = db.Column(db.Integer, nullable=False)
    token = db.Column(db.String(64), nullable=True)
    status = db.Column(db.String(20), default="pending")  # pending / paid / failed
    ref_num = db.Column(db.String(64), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)


# جدول‌های دیتابیس رو همین‌جا می‌سازیم (نه فقط داخل __main__)
# چون روی Render با gunicorn اجرا می‌شه و بلوک __main__ اجرا نمی‌شود
with app.app_context():
    db.create_all()

# ---------------------------------------------------------------
# احراز هویت با JWT
# ---------------------------------------------------------------
def generate_token(user_id):
    payload = {
        "user_id": user_id,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(days=30),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "توکن ارسال نشده"}), 401
        token = auth_header.split(" ")[1]
        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            current_user = User.query.get(data["user_id"])
            if not current_user:
                raise Exception("کاربر یافت نشد")
        except Exception:
            return jsonify({"error": "توکن نامعتبر یا منقضی شده"}), 401
        return f(current_user, *args, **kwargs)
    return decorated


# ---------------------------------------------------------------
# مسیرهای ثبت‌نام / ورود
# ---------------------------------------------------------------
@app.route("/api/signup", methods=["POST"])
def signup():
    data = request.get_json()
    phone = data.get("phone", "").strip()
    password = data.get("password", "")

    if not phone or not password:
        return jsonify({"error": "شماره موبایل و رمز عبور الزامی است"}), 400
    if len(password) < 8:
        return jsonify({"error": "رمز عبور باید حداقل ۸ کاراکتر باشد"}), 400
    if User.query.filter_by(phone=phone).first():
        return jsonify({"error": "این شماره قبلاً ثبت‌نام کرده است"}), 409

    user = User(phone=phone, password_hash=generate_password_hash(password))
    db.session.add(user)
    db.session.commit()

    # اطلاع‌رسانی به ادمین: یه کاربر جدید ثبت‌نام کرده (پیگیری برای سفارش در تلگرام)
    notify_admin_telegram(
        "👤 ثبت‌نام جدید در سایت\n"
        f"شماره: {user.phone}"
    )

    token = generate_token(user.id)
    return jsonify({"token": token, "user": user.to_dict()}), 201


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json()
    phone = data.get("phone", "").strip()
    password = data.get("password", "")

    user = User.query.filter_by(phone=phone).first()
    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({"error": "شماره موبایل یا رمز عبور اشتباه است"}), 401

    token = generate_token(user.id)
    return jsonify({"token": token, "user": user.to_dict()}), 200


@app.route("/api/me", methods=["GET"])
@token_required
def me(current_user):
    return jsonify({"user": current_user.to_dict()}), 200


# ---------------------------------------------------------------
# بات تلگرام (روش webhook، بدون نیاز به سرویس جدا)
# ---------------------------------------------------------------
TG_API = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}"

# برای عضویت اجباری قبل از استفاده از دکمه‌ها
REQUIRED_CHANNEL = os.environ.get("REQUIRED_CHANNEL", "@LPOVPN")


def is_channel_member(user_id):
    """چک می‌کنه کاربر عضو کانال هست یا نه. بات باید ادمین کانال باشه."""
    try:
        resp = requests.get(
            f"{TG_API}/getChatMember",
            params={"chat_id": REQUIRED_CHANNEL, "user_id": user_id},
            timeout=8,
        )
        result = resp.json()
        if result.get("ok"):
            status = result["result"].get("status")
            return status in ("creator", "administrator", "member")
    except Exception:
        pass
    return False


def join_channel_keyboard():
    return [
        [{"text": "📢 عضویت در کانال", "url": f"https://t.me/{REQUIRED_CHANNEL.lstrip('@')}"}],
        [{"text": "✅ عضو شدم", "callback_data": "checkjoin"}],
    ]


PLAN_LABELS = {
    1: {"title": "یک ماهه", "price": 250000},
    3: {"title": "سه ماهه", "price": 600000},
    6: {"title": "شش ماهه", "price": 1000000},
    12: {"title": "یک ساله", "price": 1700000},
}

WELCOME_TEXT = "خوش آمدید با ما آسوده خاطر وب‌گردی کنید😍"

TUTORIAL_FALLBACK_TEXT = (
    "📖 راهنمای اتصال\n\n"
    "ویدیوی آموزش به‌زودی اینجا قرار می‌گیره. فعلاً برای راهنمایی به پشتیبانی پیام بده."
)


def tg_call(method, payload):
    try:
        requests.post(f"{TG_API}/{method}", json=payload, timeout=10)
    except Exception:
        pass


def tg_send(chat_id, text, keyboard=None):
    payload = {"chat_id": chat_id, "text": text}
    if keyboard:
        payload["reply_markup"] = {"inline_keyboard": keyboard}
    tg_call("sendMessage", payload)


def tg_edit(chat_id, message_id, text, keyboard=None):
    """پیام قبلی رو در همون‌جا ویرایش می‌کنه، به‌جای فرستادن پیام جدید (که تلنبار می‌شد)."""
    payload = {"chat_id": chat_id, "message_id": message_id, "text": text}
    if keyboard:
        payload["reply_markup"] = {"inline_keyboard": keyboard}
    tg_call("editMessageText", payload)


def tg_send_video(chat_id, file_id, caption=None, keyboard=None):
    payload = {"chat_id": chat_id, "video": file_id}
    if caption:
        payload["caption"] = caption
    if keyboard:
        payload["reply_markup"] = {"inline_keyboard": keyboard}
    tg_call("sendVideo", payload)


def tg_send_document(chat_id, file_id, caption=None):
    payload = {"chat_id": chat_id, "document": file_id}
    if caption:
        payload["caption"] = caption
    tg_call("sendDocument", payload)


def main_menu_keyboard():
    return [
        [{"text": "🟢 خرید اشتراک", "callback_data": "plans"}],
        [{"text": "📖 آموزش اتصال", "callback_data": "tutorial"}],
        [{"text": "🎧 ارتباط با پشتیبانی", "url": "https://t.me/Lpovpn_solo"}],
    ]


def plans_keyboard():
    rows = []
    for key, plan in PLAN_LABELS.items():
        label = f"{plan['title']} — {plan['price']:,} تومان"
        rows.append([{"text": label, "callback_data": f"plan:{key}"}])
    rows.append([{"text": "🔴 بازگشت", "callback_data": "menu"}])
    return rows


def payment_method_keyboard(plan_key):
    rows = [[{"text": "💳 پرداخت کارت به کارت", "callback_data": f"pay:{plan_key}"}]]
    if SAMAN_TERMINAL_ID:
        rows.append([{"text": "🏦 پرداخت آنلاین با کارت بانکی", "callback_data": f"payonline:{plan_key}"}])
    rows.append([{"text": "🔴 بازگشت", "callback_data": "plans"}])
    return rows


def after_card_info_keyboard():
    return [
        [{"text": "🎧 ارتباط با پشتیبانی", "url": "https://t.me/Lpovpn_solo"}],
        [{"text": "🔴 بازگشت به منو", "callback_data": "menu"}],
    ]


def paid_confirm_keyboard():
    return [[{"text": "🟢 پرداخت کردم", "callback_data": "confirm_paid"}]]


def admin_receipt_tag_keyboard(customer_chat_id):
    return [[{"text": "✅ تایید کن", "callback_data": f"approve:{customer_chat_id}"}]]


def back_to_menu_keyboard():
    return [[{"text": "🔴 بازگشت به منو", "callback_data": "menu"}]]


def upsert_contact(chat_id, username, first_name):
    contact = TelegramContact.query.get(str(chat_id))
    if not contact:
        contact = TelegramContact(chat_id=str(chat_id))
        db.session.add(contact)
    contact.username = username
    contact.first_name = first_name
    db.session.commit()


def set_selected_plan(chat_id, plan_key):
    session_row = BotSession.query.get(str(chat_id))
    if not session_row:
        session_row = BotSession(chat_id=str(chat_id))
        db.session.add(session_row)
    session_row.selected_plan = plan_key
    db.session.commit()


def get_selected_plan(chat_id):
    session_row = BotSession.query.get(str(chat_id))
    return session_row.selected_plan if session_row else None


def get_tutorial_video_id():
    media = BotMedia.query.get("tutorial_video")
    return media.file_id if media else None


def set_tutorial_video_id(file_id):
    media = BotMedia.query.get("tutorial_video")
    if not media:
        media = BotMedia(key="tutorial_video")
        db.session.add(media)
    media.file_id = file_id
    db.session.commit()


# ---------------------------------------------------------------
# درگاه پرداخت بانک سامان (سپ)
# ---------------------------------------------------------------
def saman_create_token(res_num, amount_toman):
    """از درگاه سامان یه توکن پرداخت می‌گیره. مبلغ باید به ریال فرستاده بشه (تومان × ۱۰)."""
    amount_rial = amount_toman * 10
    payload = {
        "action": "token",
        "TerminalId": int(SAMAN_TERMINAL_ID),
        "Amount": amount_rial,
        "ResNum": res_num,
        "RedirectUrl": f"{SAMAN_SITE_BASE_URL}/api/saman/callback",
    }
    try:
        resp = requests.post(SAMAN_TOKEN_URL, json=payload, timeout=15)
        result = resp.json()
    except Exception:
        return None

    if result.get("status") == 1 and result.get("token"):
        return result["token"]
    return None


def saman_verify(ref_num):
    """تایید نهایی تراکنش بعد از بازگشت کاربر از بانک."""
    payload = {
        "RefNum": ref_num,
        "TerminalNumber": int(SAMAN_TERMINAL_ID),
    }
    try:
        resp = requests.post(SAMAN_VERIFY_URL, json=payload, timeout=15)
        return resp.json()
    except Exception:
        return None


@app.route("/pay/saman/<res_num>", methods=["GET"])
def saman_redirect_page(res_num):
    """یه صفحه واسط که کاربر رو خودکار به درگاه بانک سامان می‌فرسته (چون بانک فقط POST قبول می‌کنه)."""
    order = SamanOrder.query.get(res_num)
    if not order or not order.token:
        return "سفارش یافت نشد یا منقضی شده است.", 404

    html = f"""
    <!DOCTYPE html>
    <html lang="fa" dir="rtl">
    <head><meta charset="UTF-8"><title>در حال انتقال به درگاه بانک...</title></head>
    <body style="font-family:sans-serif; text-align:center; padding-top:80px;">
        <p>در حال انتقال به درگاه پرداخت بانک سامان...</p>
        <form id="samanForm" method="POST" action="{SAMAN_REDIRECT_FORM_URL}">
            <input type="hidden" name="Token" value="{order.token}">
            <input type="hidden" name="GetMethod" value="true">
        </form>
        <script>document.getElementById('samanForm').submit();</script>
    </body>
    </html>
    """
    return html


@app.route("/api/saman/callback", methods=["POST"])
def saman_callback():
    state = request.form.get("State")
    res_num = request.form.get("ResNum")
    ref_num = request.form.get("RefNum")

    order = SamanOrder.query.get(res_num) if res_num else None
    if not order:
        return "سفارش یافت نشد.", 404

    if state != "OK":
        order.status = "failed"
        db.session.commit()
        tg_send(order.chat_id, "❌ پرداخت لغو شد یا ناموفق بود. می‌تونی دوباره تلاش کنی یا از کارت‌به‌کارت استفاده کنی.")
        return "پرداخت ناموفق بود. این پنجره رو ببندید و به بات برگردید."

    verify_result = saman_verify(ref_num)
    verified_amount = None
    if verify_result:
        # پاسخ درگاه سامان معمولاً یا عدد مبلغ تایید‌شده‌ست، یا آبجکتی با فیلد amount/Amount
        if isinstance(verify_result, (int, float)):
            verified_amount = int(verify_result)
        elif isinstance(verify_result, dict):
            verified_amount = verify_result.get("Amount") or verify_result.get("amount")

    expected_rial = order.amount_toman * 10
    if verified_amount and int(verified_amount) == expected_rial:
        order.status = "paid"
        order.ref_num = ref_num
        db.session.commit()

        plan = PLAN_LABELS.get(order.plan_key, {})
        tg_send(
            order.chat_id,
            "✅ پرداخت شما با موفقیت تایید شد!\nبه‌زودی اطلاعات سرور برات ارسال می‌شه."
        )
        notify_admin_telegram(
            "🟢 پرداخت آنلاین موفق (درگاه سامان)\n"
            f"چت‌آیدی: {order.chat_id}\n"
            f"پلن: {plan.get('title', order.plan_key)}\n"
            f"مبلغ: {order.amount_toman:,} تومان\n"
            f"شماره پیگیری: {ref_num}\n\n"
            f"برای ارسال فایل سرور:\n/sendfile {order.chat_id}"
        )
        return "پرداخت با موفقیت تایید شد. این پنجره رو ببندید و به بات برگردید."
    else:
        order.status = "failed"
        db.session.commit()
        tg_send(order.chat_id, "❌ تایید تراکنش ناموفق بود. لطفاً با پشتیبانی تماس بگیر.")
        return "خطا در تایید تراکنش.", 502


@app.route("/api/telegram/webhook", methods=["POST"])
def telegram_webhook():
    update = request.get_json(silent=True) or {}

    # ================= پیام‌های معمولی (متن، عکس، ویدیو، فایل) =================
    if "message" in update:
        msg = update["message"]
        chat_id = msg["chat"]["id"]
        from_user = msg.get("from", {})
        username = from_user.get("username")
        first_name = from_user.get("first_name", "")
        is_admin = str(chat_id) == str(TELEGRAM_ADMIN_CHAT_ID)

        # ---------- دستورات مخصوص ادمین ----------
        if is_admin:
            text = (msg.get("text") or "").strip()
            caption = (msg.get("caption") or "").strip()

            if text.startswith("/broadcast"):
                broadcast_text = text[len("/broadcast"):].strip()
                if broadcast_text:
                    contacts = TelegramContact.query.all()
                    for c in contacts:
                        tg_send(c.chat_id, broadcast_text)
                    tg_send(chat_id, f"✅ پیام به {len(contacts)} مخاطب ارسال شد.")
                else:
                    tg_send(chat_id, "فرمت درست: /broadcast متن پیام")
                return jsonify({"ok": True})

            if text.startswith("/send"):
                parts = text.split(" ", 2)
                if len(parts) == 3:
                    target_chat_id, message_text = parts[1], parts[2]
                    tg_send(target_chat_id, message_text)
                    tg_send(chat_id, f"✅ پیام به {target_chat_id} ارسال شد.")
                else:
                    tg_send(chat_id, "فرمت درست: /send <chat_id> <متن پیام>")
                return jsonify({"ok": True})

            # ویدیوی آموزش عمومی (قابل مشاهده برای همه کاربران)
            if "video" in msg and caption == "/settutorial":
                set_tutorial_video_id(msg["video"]["file_id"])
                tg_send(chat_id, "✅ ویدیوی آموزش ذخیره شد. از این به بعد برای همه کاربران نمایش داده می‌شه.")
                return jsonify({"ok": True})

            # ارسال فایل سرور فقط برای یک مشتری خاص (بعد از تایید پرداخت)
            if "document" in msg and caption.startswith("/sendfile"):
                parts = caption.split(" ", 1)
                if len(parts) == 2:
                    target_chat_id = parts[1].strip()
                    tg_send_document(target_chat_id, msg["document"]["file_id"], caption="📦 فایل سرور شما")
                    tg_send(chat_id, f"✅ فایل برای {target_chat_id} ارسال شد.")
                else:
                    tg_send(chat_id, "فرمت درست: کپشن فایل رو بذار /sendfile <chat_id>")
                return jsonify({"ok": True})

            # اگه دستور خاصی نبود ولی ادمین /start زد، منوی عادی رو ببینه
            if text != "/start":
                return jsonify({"ok": True})

        # ---------- دستور شروع (برای همه، ازجمله ادمین) ----------
        if msg.get("text") == "/start":
            upsert_contact(chat_id, username, first_name)
            tg_send(chat_id, WELCOME_TEXT, keyboard=main_menu_keyboard())

            if not is_admin:
                uname_display = f"@{username}" if username else "(بدون یوزرنیم)"
                notify_admin_telegram(
                    "🆕 استارت جدید در بات\n"
                    f"نام: {first_name}\n"
                    f"یوزرنیم: {uname_display}\n"
                    f"چت‌آیدی: {chat_id}"
                )
            return jsonify({"ok": True})

        # ---------- عکس رسید پرداخت (فقط از طرف مشتری‌ها) ----------
        if "photo" in msg and not is_admin:
            # پیام رسید رو ذخیره می‌کنیم تا وقتی کاربر دکمه «پرداخت کردم» رو زد، فوروارد بشه
            session_row = BotSession.query.get(str(chat_id))
            if not session_row:
                session_row = BotSession(chat_id=str(chat_id))
                db.session.add(session_row)
            session_row.last_receipt_message_id = msg["message_id"]
            db.session.commit()

            tg_send(
                chat_id,
                "رسید شما دریافت شد 🧾\nاگه واریز رو کامل انجام دادی، روی دکمه زیر بزن تا برای بررسی ارسال بشه:",
                keyboard=paid_confirm_keyboard(),
            )
            return jsonify({"ok": True})

        # ---------- هر پیام دیگه‌ای از مشتری ----------
        if not is_admin:
            tg_send(chat_id, "برای مشاهده گزینه‌ها از منوی زیر استفاده کن:", keyboard=main_menu_keyboard())

        return jsonify({"ok": True})

    # ================= دکمه‌های شیشه‌ای =================
    if "callback_query" in update:
        cq = update["callback_query"]
        chat_id = cq["message"]["chat"]["id"]
        message_id = cq["message"]["message_id"]
        data = cq.get("data", "")
        user_id = cq.get("from", {}).get("id", chat_id)
        is_admin = str(chat_id) == str(TELEGRAM_ADMIN_CHAT_ID)

        # جواب سریع به تلگرام تا لودینگ دکمه قطع بشه
        tg_call("answerCallbackQuery", {"callback_query_id": cq["id"]})

        # عضویت اجباری در کانال (به‌جز خود ادمین و خود دکمه بررسی عضویت)
        if not is_admin and data != "checkjoin" and not is_channel_member(user_id):
            tg_edit(
                chat_id, message_id,
                "برای استفاده از امکانات بات، اول باید عضو کانال ما بشی:",
                keyboard=join_channel_keyboard(),
            )
            return jsonify({"ok": True})

        if data == "checkjoin":
            if is_channel_member(user_id) or is_admin:
                tg_edit(chat_id, message_id, "✅ عضویت تایید شد. منوی اصلی:", keyboard=main_menu_keyboard())
            else:
                tg_edit(
                    chat_id, message_id,
                    "هنوز عضو کانال نشدی. اول عضو شو، بعد دوباره امتحان کن:",
                    keyboard=join_channel_keyboard(),
                )
            return jsonify({"ok": True})

        if data == "menu":
            tg_edit(chat_id, message_id, "منوی اصلی:", keyboard=main_menu_keyboard())

        elif data == "noop":
            pass  # دکمه تزئینی، کاری انجام نمی‌ده

        elif data.startswith("approve:"):
            target_chat_id = data.split(":", 1)[1]
            tg_send(target_chat_id, "✅ پرداخت شما تایید شد!\nبه‌زودی اطلاعات سرور برات ارسال می‌شه.")
            tg_edit(
                chat_id, message_id,
                cq["message"].get("text", "") + "\n\n✅ تایید شد توسط پشتیبانی.\nبرای ارسال فایل سرور:\n"
                f"/sendfile {target_chat_id}",
            )

        elif data == "confirm_paid":
            session_row = BotSession.query.get(str(chat_id))
            receipt_message_id = session_row.last_receipt_message_id if session_row else None

            if not receipt_message_id:
                tg_edit(chat_id, message_id, "رسیدی پیدا نشد. لطفاً اول عکس رسید رو ارسال کن.", keyboard=back_to_menu_keyboard())
            else:
                contact = TelegramContact.query.get(str(chat_id))
                uname = contact.username if contact else None
                fname = contact.first_name if contact else ""
                uname_display = f"@{uname}" if uname else "(بدون یوزرنیم)"

                plan_key = get_selected_plan(chat_id)
                plan_info = PLAN_LABELS.get(plan_key) if plan_key else None
                plan_text = f"{plan_info['title']} — {plan_info['price']:,} تومان" if plan_info else "نامشخص"

                tg_call("forwardMessage", {
                    "chat_id": TELEGRAM_ADMIN_CHAT_ID,
                    "from_chat_id": chat_id,
                    "message_id": receipt_message_id,
                })
                tg_send(
                    TELEGRAM_ADMIN_CHAT_ID,
                    "🧾 رسید پرداخت تایید شد (کاربر دکمه پرداخت‌کردم رو زد)\n"
                    f"نام: {fname}\n"
                    f"یوزرنیم: {uname_display}\n"
                    f"چت‌آیدی: {chat_id}\n"
                    f"پلن انتخابی: {plan_text}\n\n"
                    f"برای ارسال فایل سرور:\n/sendfile {chat_id}\n\n"
                    f"یا برای پیام متنی:\n/send {chat_id} <پیام>",
                    keyboard=admin_receipt_tag_keyboard(chat_id),
                )
                tg_edit(chat_id, message_id, "رسید شما برای بررسی ارسال شد ✅\nبعد از تایید پشتیبانی، اطلاعات سرور برات ارسال می‌شه.")

        elif data == "plans":
            tg_edit(chat_id, message_id, "یکی از پلن‌ها رو انتخاب کن (همه نامحدود):", keyboard=plans_keyboard())

        elif data == "tutorial":
            video_id = get_tutorial_video_id()
            if video_id:
                # پیام قبلی رو کوچیک می‌کنیم و ویدیو رو جدا می‌فرستیم (نمی‌شه متن رو به ویدیو ادیت کرد)
                tg_edit(chat_id, message_id, "📖 در حال ارسال ویدیوی آموزش...")
                tg_send_video(
                    chat_id, video_id,
                    caption="📖 آموزش اتصال\n\nاگه سوالی داشتی، از دکمه پشتیبانی زیر همین پیام استفاده کن.",
                    keyboard=after_card_info_keyboard(),
                )
            else:
                tg_edit(chat_id, message_id, TUTORIAL_FALLBACK_TEXT, keyboard=back_to_menu_keyboard())

        elif data.startswith("plan:"):
            plan_key = int(data.split(":")[1])
            set_selected_plan(chat_id, plan_key)
            plan = PLAN_LABELS[plan_key]
            tg_edit(
                chat_id, message_id,
                f"پلن انتخابی: {plan['title']}\nمبلغ: {plan['price']:,} تومان\n\nروش پرداخت رو انتخاب کن:",
                keyboard=payment_method_keyboard(plan_key),
            )

        elif data.startswith("pay:"):
            plan_key = int(data.split(":")[1])
            plan = PLAN_LABELS[plan_key]
            tg_edit(
                chat_id, message_id,
                f"💳 پرداخت کارت به کارت\n\n"
                f"شماره کارت:\n{CARD_NUMBER}\n\n"
                f"به نام: {CARD_HOLDER_NAME}\n\n"
                f"مبلغ قابل پرداخت: {plan['price']:,} تومان ({plan['title']})\n\n"
                "⚠️ حتماً بعد از واریز، از رسید پرداخت اسکرین‌شات بگیر و همینجا برای من ارسال کن.\n"
                "بعد از تایید، اطلاعات سرور برات ارسال می‌شه.",
                keyboard=after_card_info_keyboard(),
            )

        elif data.startswith("payonline:"):
            plan_key = int(data.split(":")[1])
            plan = PLAN_LABELS[plan_key]
            res_num = f"{chat_id}-{uuid.uuid4().hex[:10]}"

            order = SamanOrder(
                res_num=res_num,
                chat_id=str(chat_id),
                plan_key=plan_key,
                amount_toman=plan["price"],
                status="pending",
            )
            db.session.add(order)
            db.session.commit()

            token = saman_create_token(res_num, plan["price"])
            if token:
                order.token = token
                db.session.commit()
                pay_url = f"{SAMAN_SITE_BASE_URL}/pay/saman/{res_num}"
                tg_edit(
                    chat_id, message_id,
                    f"🏦 پرداخت آنلاین — {plan['title']}\n"
                    f"مبلغ: {plan['price']:,} تومان\n\n"
                    "روی دکمه زیر بزن و پرداخت رو تکمیل کن. بعد از پرداخت موفق، خودکار بهت خبر می‌دیم.",
                    keyboard=[
                        [{"text": "💳 رفتن به درگاه پرداخت", "url": pay_url}],
                        [{"text": "🔴 بازگشت", "callback_data": f"plan:{plan_key}"}],
                    ],
                )
            else:
                order.status = "failed"
                db.session.commit()
                tg_edit(
                    chat_id, message_id,
                    "⚠️ درگاه پرداخت آنلاین موقتاً در دسترس نیست.\nلطفاً از روش کارت‌به‌کارت استفاده کن.",
                    keyboard=payment_method_keyboard(plan_key),
                )

        return jsonify({"ok": True})

    return jsonify({"ok": True})



# ---------------------------------------------------------------
# اجرا
# ---------------------------------------------------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5000)
