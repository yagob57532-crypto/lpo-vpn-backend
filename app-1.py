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

# ⚠️ این مقادیر رو حتماً در نسخهٔ نهایی از متغیرهای محیطی (environment variables) بخون، نه هاردکد در کد
SECRET_KEY = os.environ.get("SECRET_KEY", "CHANGE-THIS-TO-A-RANDOM-SECRET")
ZARINPAL_MERCHANT_ID = os.environ.get("ZARINPAL_MERCHANT_ID", "YOUR-MERCHANT-ID")
ZARINPAL_SANDBOX = True  # موقع رفتن به حالت واقعی، این رو False کن

ZP_BASE = "https://sandbox.zarinpal.com" if ZARINPAL_SANDBOX else "https://payment.zarinpal.com"
ZP_REQUEST_URL = f"{ZP_BASE}/pg/v4/payment/request.json"
ZP_VERIFY_URL = f"{ZP_BASE}/pg/v4/payment/verify.json"
ZP_STARTPAY_URL = f"{ZP_BASE}/pg/StartPay/"

CALLBACK_URL = os.environ.get("CALLBACK_URL", "http://localhost:5000/api/payment/callback")

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


class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    plan_months = db.Column(db.Integer, nullable=False)
    amount_toman = db.Column(db.Integer, nullable=False)
    authority = db.Column(db.String(64), nullable=True)  # کد پیگیری زرین‌پال
    ref_id = db.Column(db.String(64), nullable=True)  # کد مرجع بعد از تایید پرداخت
    status = db.Column(db.String(20), default="pending")  # pending / paid / failed
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)


# پلن‌های اشتراک (باید با چیزی که در dashboard.html نشون داده می‌شه هماهنگ باشه)
PLANS = {
    1: {"months": 1, "price": 99000},
    6: {"months": 6, "price": 475000},
    12: {"months": 12, "price": 770000},
}

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
    # سه روز اشتراک رایگان آزمایشی
    user.subscription_end = datetime.datetime.utcnow() + datetime.timedelta(days=3)
    db.session.add(user)
    db.session.commit()

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
# پرداخت با زرین‌پال
# ---------------------------------------------------------------
@app.route("/api/payment/request", methods=["POST"])
@token_required
def payment_request(current_user):
    data = request.get_json()
    plan_key = data.get("plan")  # 1, 6, یا 12

    if plan_key not in PLANS:
        return jsonify({"error": "پلن نامعتبر است"}), 400

    plan = PLANS[plan_key]

    order = Order(
        user_id=current_user.id,
        plan_months=plan["months"],
        amount_toman=plan["price"],
        status="pending",
    )
    db.session.add(order)
    db.session.commit()

    # زرین‌پال مبلغ رو به ریال می‌گیره
    amount_rial = plan["price"] * 10

    payload = {
        "merchant_id": ZARINPAL_MERCHANT_ID,
        "amount": amount_rial,
        "callback_url": f"{CALLBACK_URL}?order_id={order.id}",
        "description": f"خرید اشتراک {plan['months']} ماهه LPO VPN",
        "metadata": {"mobile": current_user.phone},
    }

    try:
        resp = requests.post(ZP_REQUEST_URL, json=payload, timeout=10)
        result = resp.json()
    except Exception as e:
        return jsonify({"error": f"خطا در ارتباط با درگاه پرداخت: {e}"}), 502

    if result.get("data") and result["data"].get("code") == 100:
        authority = result["data"]["authority"]
        order.authority = authority
        db.session.commit()
        return jsonify({
            "payment_url": f"{ZP_STARTPAY_URL}{authority}",
            "order_id": order.id,
        }), 200
    else:
        order.status = "failed"
        db.session.commit()
        errors = result.get("errors", {})
        return jsonify({"error": "خطا در ایجاد تراکنش", "details": errors}), 502


@app.route("/api/payment/callback", methods=["GET"])
def payment_callback():
    order_id = request.args.get("order_id")
    authority = request.args.get("Authority")
    status = request.args.get("Status")

    order = Order.query.get(order_id)
    if not order:
        return "سفارش یافت نشد", 404

    if status != "OK":
        order.status = "failed"
        db.session.commit()
        # در نسخه واقعی، کاربر رو به یک صفحه HTML "پرداخت ناموفق" ریدایرکت کن
        return "پرداخت لغو شد یا ناموفق بود."

    amount_rial = order.amount_toman * 10
    payload = {
        "merchant_id": ZARINPAL_MERCHANT_ID,
        "amount": amount_rial,
        "authority": authority,
    }

    try:
        resp = requests.post(ZP_VERIFY_URL, json=payload, timeout=10)
        result = resp.json()
    except Exception as e:
        return f"خطا در تایید تراکنش: {e}", 502

    if result.get("data") and result["data"].get("code") in (100, 101):
        order.status = "paid"
        order.ref_id = str(result["data"].get("ref_id"))
        db.session.commit()

        # تمدید اشتراک کاربر
        user = User.query.get(order.user_id)
        now = datetime.datetime.utcnow()
        base = user.subscription_end if (user.subscription_end and user.subscription_end > now) else now
        user.subscription_end = base + datetime.timedelta(days=30 * order.plan_months)
        db.session.commit()

        # در نسخه واقعی، این رو به یک صفحه HTML "پرداخت موفق" ریدایرکت کن
        return f"پرداخت با موفقیت انجام شد. کد پیگیری: {order.ref_id}"
    else:
        order.status = "failed"
        db.session.commit()
        return "تایید تراکنش ناموفق بود.", 502


# ---------------------------------------------------------------
# اجرا
# ---------------------------------------------------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True, port=5000)
