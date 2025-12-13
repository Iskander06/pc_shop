import os
import uuid
import re
from time import time
from functools import wraps

import requests
from flask import (
    Flask, render_template, url_for,
    redirect, request, session, flash
)
from flask_sqlalchemy import SQLAlchemy
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

# SendGrid (опционально: если не установлен, будет фолбэк на "печать письма в консоль")
try:
    from sendgrid import SendGridAPIClient
    from sendgrid.helpers.mail import Mail
    SENDGRID_AVAILABLE = True
except Exception:
    SENDGRID_AVAILABLE = False


# -----------------------------------
#             НАСТРОЙКИ
# -----------------------------------

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(BASE_DIR, ".env"))

app = Flask(__name__)

# SECRET KEY
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "dev-secret-key")


# -----------------------------------
#       НАСТРОЙКИ БАЗЫ ДАННЫХ
# -----------------------------------

DATABASE_URL = os.getenv("DATABASE_URL")

if DATABASE_URL:
    # Render / production
    if DATABASE_URL.startswith("postgres://"):
        DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg://", 1)
    elif DATABASE_URL.startswith("postgresql://"):
        DATABASE_URL = DATABASE_URL.replace("postgresql://", "postgresql+psycopg://", 1)

    app.config["SQLALCHEMY_DATABASE_URI"] = DATABASE_URL
else:
    # Local development
    db_user = os.getenv("DB_USER", "postgres")
    db_pass = os.getenv("DB_PASS", "1234")
    db_host = os.getenv("DB_HOST", "localhost")
    db_port = os.getenv("DB_PORT", "5432")
    db_name = os.getenv("DB_NAME", "pc_shop")

    app.config["SQLALCHEMY_DATABASE_URI"] = (
        f"postgresql+psycopg://{db_user}:{db_pass}@{db_host}:{db_port}/{db_name}"
    )

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
print("DB URI:", app.config["SQLALCHEMY_DATABASE_URI"])


# -----------------------------------
#     ЗАГРУЗКА ФАЙЛОВ / SQLALCHEMY
# -----------------------------------

UPLOAD_FOLDER = os.path.join(app.static_folder, "uploads")
AVATAR_FOLDER = os.path.join(UPLOAD_FOLDER, "avatars")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(AVATAR_FOLDER, exist_ok=True)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["AVATAR_FOLDER"] = AVATAR_FOLDER

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}

db = SQLAlchemy(app)


# -----------------------------------
#       ПЕРЕМЕННЫЕ / ИНТЕГРАЦИИ
# -----------------------------------

# Telegram
TG_BOT_LINK = os.getenv("TG_BOT_LINK", "https://t.me/your_bot_here")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")

# Email via SendGrid
SENDGRID_API_KEY = os.getenv("SENDGRID_API_KEY")
MAIL_FROM = os.getenv("MAIL_FROM")  # например: "no-reply@yourdomain.com"

# Города
CITIES = [
    "Алматы",
    "Астана",
    "Шымкент",
    "Караганда",
    "Актобе",
    "Тараз",
    "Павлодар",
    "Усть-Каменогорск",
    "Семей",
    "Костанай",
    "Кызылорда",
    "Уральск",
    "Петропавловск",
]


# -----------------------------------
#             МОДЕЛИ
# -----------------------------------

class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(36), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    last_name = db.Column(db.String(100), nullable=False)
    first_name = db.Column(db.String(100), nullable=False)
    middle_name = db.Column(db.String(100), nullable=False)
    city = db.Column(db.String(100), nullable=False)

    phone = db.Column(db.String(20), nullable=True)
    avatar_image = db.Column(db.String(255), nullable=True)

    role = db.Column(db.String(10), default="user", nullable=False)  # user/admin
    is_blocked = db.Column(db.Boolean, default=False, nullable=False)
    is_email_verified = db.Column(db.Boolean, default=False, nullable=False)

    orders = db.relationship("Order", backref="user", lazy=True)
    cart_items = db.relationship("CartItem", backref="user", lazy=True)

    def full_name(self):
        return f"{self.last_name} {self.first_name} {self.middle_name}"


class Product(db.Model):
    __tablename__ = "products"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Integer, nullable=False)
    image = db.Column(db.String(255), nullable=True)  # static/uploads/...


class CartItem(db.Model):
    __tablename__ = "cart_items"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey("products.id"), nullable=False)
    quantity = db.Column(db.Integer, default=1, nullable=False)

    product = db.relationship("Product")


class Order(db.Model):
    __tablename__ = "orders"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)

    status = db.Column(db.String(20), default="new", nullable=False)  # new/in_progress/completed
    confirmed = db.Column(db.Boolean, default=False, nullable=False)  # подтверждён админом

    items = db.relationship("OrderItem", backref="order", lazy=True)


class OrderItem(db.Model):
    __tablename__ = "order_items"

    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey("orders.id"), nullable=False)
    product_id = db.Column(db.Integer, db.ForeignKey("products.id"), nullable=False)
    quantity = db.Column(db.Integer, default=1, nullable=False)

    product = db.relationship("Product")


class EmailLog(db.Model):
    __tablename__ = "email_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    email = db.Column(db.String(120), nullable=False)
    subject = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(20), nullable=False)  # sent/failed
    error = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, server_default=db.func.now())


# -----------------------------------
#       ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# -----------------------------------

def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def get_current_user():
    user_id = session.get("user_id")
    if user_id is None:
        return None
    return db.session.get(User, user_id)



def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Сначала войдите в аккаунт.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if session.get("role") != "admin":
            return "Доступ запрещён", 403
        return f(*args, **kwargs)
    return wrapper


def send_telegram_message(text: str):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        data = {
            "chat_id": TELEGRAM_CHAT_ID,
            "text": text,
            "parse_mode": "HTML",
        }
        requests.post(url, data=data, timeout=5)
    except Exception as e:
        print(f"Ошибка отправки сообщения в Telegram: {e}")


def send_email(to_email: str, subject: str, body: str, user: User | None = None):
    api_key = os.getenv("SENDGRID_API_KEY")
    mail_from = os.getenv("MAIL_FROM")

    log = EmailLog(
        user_id=user.id if user else None,
        email=to_email,
        subject=subject,
        status="failed"
    )

    try:
        if not api_key or not mail_from:
            raise Exception("SendGrid не настроен")

        message = Mail(
            from_email=mail_from,
            to_emails=to_email,
            subject=subject,
            plain_text_content=body
        )

        sg = SendGridAPIClient(api_key)
        sg.send(message)

        log.status = "sent"

    except Exception as e:
        log.error = str(e)
        print("Ошибка отправки email:", e)

    finally:
        db.session.add(log)
        db.session.commit()


def generate_email_token(email: str) -> str:
    s = URLSafeTimedSerializer(app.config["SECRET_KEY"])
    return s.dumps(email)


def confirm_email_token(token: str, max_age: int = 60 * 60 * 24) -> str | None:
    s = URLSafeTimedSerializer(app.config["SECRET_KEY"])
    try:
        email = s.loads(token, max_age=max_age)
        return email
    except (BadSignature, SignatureExpired):
        return None


def send_verification_email(user: User):
    token = generate_email_token(user.email)
    verify_url = url_for("verify_email", token=token, _external=True)
    subject = "Подтверждение регистрации в PC Shop"
    body = (
        f"Здравствуйте, {user.first_name}!\n\n"
        f"Для подтверждения email перейдите по ссылке:\n{verify_url}\n\n"
        f"Если вы не регистрировались на сайте PC Shop, просто проигнорируйте это письмо."
    )
    send_email(user.email, subject, body, user=user)


@app.context_processor
def inject_globals():
    user = get_current_user()
    cart_count = 0
    if user:
        cart_count = CartItem.query.filter_by(user_id=user.id).count()

    return {
        "current_user": user,
        "cart_count": cart_count,
        "tg_bot_link": TG_BOT_LINK,
        "CITIES": CITIES,
    }


# -----------------------------------
#           ВАЛИДАЦИЯ
# -----------------------------------

def is_valid_name(name: str) -> bool:
    return bool(re.match(r"^[A-Za-zА-Яа-яЁё\- ]+$", name))


def is_valid_user_email(email: str) -> bool:
    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        return False

    if email.endswith(".local"):
        return False

    domain_part = email.split("@")[-1]
    tld = domain_part.split(".")[-1].lower()
    allowed_tlds = {"com", "ru", "kz", "net", "org", "mail"}
    return tld in allowed_tlds


def is_valid_kz_phone(phone: str) -> bool:
    return bool(re.match(r"^\+7\d{10}$", phone))


# -----------------------------------
#           АВТОРИЗАЦИЯ
# -----------------------------------

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")
        password2 = request.form.get("password2", "")

        last_name = request.form.get("last_name", "").strip()
        first_name = request.form.get("first_name", "").strip()
        middle_name = request.form.get("middle_name", "").strip()
        city = request.form.get("city", "").strip()
        phone = request.form.get("phone", "").strip()

        errors = []

        if not email:
            errors.append("Email обязателен.")
        elif not is_valid_user_email(email):
            errors.append("Email имеет недопустимый формат. Используйте домены .com, .ru, .kz, .net, .org, .mail и т.п.")

        if not password:
            errors.append("Пароль обязателен.")
        elif len(password) < 6:
            errors.append("Пароль должен быть не меньше 6 символов.")
        if password != password2:
            errors.append("Пароли не совпадают.")

        if not last_name:
            errors.append("Фамилия обязательна.")
        elif not is_valid_name(last_name):
            errors.append("Фамилия может содержать только буквы, пробел и дефис.")

        if not first_name:
            errors.append("Имя обязательно.")
        elif not is_valid_name(first_name):
            errors.append("Имя может содержать только буквы, пробел и дефис.")

        if not middle_name:
            errors.append("Отчество обязательно.")
        elif not is_valid_name(middle_name):
            errors.append("Отчество может содержать только буквы, пробел и дефис.")

        if not city:
            errors.append("Город обязателен.")
        elif city not in CITIES:
            errors.append("Выберите город из списка.")

        if not phone:
            errors.append("Номер телефона обязателен.")
        elif not is_valid_kz_phone(phone):
            errors.append("Номер телефона должен быть в формате +7XXXXXXXXXX (Казахстан).")

        if User.query.filter_by(email=email).first():
            errors.append("Пользователь с таким email уже существует.")

        if errors:
            for e in errors:
                flash(e, "danger")
            return render_template(
                "auth/register.html",
                form_data={
                    "email": email,
                    "last_name": last_name,
                    "first_name": first_name,
                    "middle_name": middle_name,
                    "city": city,
                    "phone": phone,
                },
            )

        user = User(
            email=email,
            password_hash=generate_password_hash(password),
            last_name=last_name,
            first_name=first_name,
            middle_name=middle_name,
            city=city,
            phone=phone,
            role="user",
            public_id=str(uuid.uuid4()),
            is_email_verified=False,
        )
        db.session.add(user)
        db.session.commit()

        # письмо подтверждения (если не настроено — будет фолбэк/лог)
        send_verification_email(user)
        flash("Регистрация прошла успешно! Проверьте почту и подтвердите email.", "success")

        return redirect(url_for("login"))

    return render_template("auth/register.html", form_data={})


@app.route("/verify-email/<token>")
def verify_email(token):
    email = confirm_email_token(token)
    if not email:
        flash("Ссылка для подтверждения email недействительна или устарела.", "danger")
        return redirect(url_for("login"))

    user = User.query.filter_by(email=email).first()
    if not user:
        flash("Пользователь не найден.", "danger")
        return redirect(url_for("login"))

    if user.is_email_verified:
        flash("Email уже был подтверждён ранее.", "info")
    else:
        user.is_email_verified = True
        db.session.commit()
        flash("Email успешно подтверждён! Теперь вы можете оформлять заказы.", "success")

    return redirect(url_for("profile"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter_by(email=email).first()

        if user and check_password_hash(user.password_hash, password):
            if user.is_blocked:
                flash("Ваш аккаунт заблокирован. Обратитесь к администратору.", "danger")
                return redirect(url_for("login"))

            session["user_id"] = user.id
            session["role"] = user.role

            if not user.is_email_verified and user.role != "admin":
                flash("⚠ Email не подтверждён. Оформление заказов будет недоступно, пока не подтвердите почту.", "warning")
            else:
                flash("Вы успешно вошли в аккаунт.", "success")

            return redirect(url_for("profile"))
        else:
            flash("Неверный email или пароль.", "danger")

    return render_template("auth/login.html")


@app.route("/resend-verification")
@login_required
def resend_verification():
    """
    Повторная отправка письма подтверждения:
    - не чаще 1 раза в 60 секунд
    - пишет лог в БД
    """
    user = get_current_user()

    if user.is_email_verified:
        flash("Email уже подтверждён.", "info")
        return redirect(url_for("profile"))

    last_sent = session.get("last_verification_email_time")
    if last_sent and time() - last_sent < 60:
        flash("Подождите 60 секунд перед повторной отправкой письма.", "warning")
        return redirect(url_for("profile"))

    send_verification_email(user)
    session["last_verification_email_time"] = time()

    flash("Письмо отправлено повторно. Проверьте почту.", "success")
    return redirect(url_for("profile"))


@app.route("/logout")
def logout():
    session.clear()
    flash("Вы вышли из аккаунта.", "info")
    return redirect(url_for("index"))


# -----------------------------------
#       СТРАНИЦЫ МАГАЗИНА
# -----------------------------------

@app.route("/")
def index():
    promos = [
        {"title": "Скидка 20% на игровые ноутбуки", "text": "Только до конца месяца! Собери идеальный игровой сетап."},
        {"title": "Сборка ПК под ключ", "text": "Подберём комплектующие и соберём ПК под твои задачи."},
        {"title": "Бесплатная диагностика", "text": "Принеси свой ПК в сервис-центр и получи первичную диагностику бесплатно."},
    ]
    return render_template("index.html", promos=promos)


@app.route("/catalog")
def catalog():
    products = Product.query.all()
    return render_template("catalog.html", products=products)


@app.route("/product/<int:product_id>")
def product_detail(product_id):
    product = Product.query.get_or_404(product_id)
    return render_template("product_detail.html", product=product)


@app.route("/about")
def about():
    return render_template("about.html")


# -----------------------------------
#           КОРЗИНА / ЗАКАЗЫ
# -----------------------------------

@app.route("/cart")
@login_required
def cart():
    user = get_current_user()
    items = CartItem.query.filter_by(user_id=user.id).all()
    total = sum(item.product.price * item.quantity for item in items)
    return render_template("cart.html", items=items, total=total)


@app.route("/cart/add/<int:product_id>", methods=["POST"])
@login_required
def add_to_cart(product_id):
    user = get_current_user()
    product = Product.query.get_or_404(product_id)

    item = CartItem.query.filter_by(user_id=user.id, product_id=product.id).first()
    if item:
        item.quantity += 1
    else:
        item = CartItem(user_id=user.id, product_id=product.id, quantity=1)
        db.session.add(item)

    db.session.commit()
    flash("Товар добавлен в корзину.", "success")
    return redirect(url_for("cart"))


@app.route("/cart/remove/<int:item_id>", methods=["POST"])
@login_required
def remove_from_cart(item_id):
    user = get_current_user()
    item = CartItem.query.get_or_404(item_id)

    if item.user_id != user.id:
        return "Запрещено", 403

    db.session.delete(item)
    db.session.commit()
    flash("Товар удалён из корзины.", "info")
    return redirect(url_for("cart"))


@app.route("/cart/checkout", methods=["POST"])
@login_required
def checkout():
    user = get_current_user()

    # ✅ Запрещаем оформление заказа, пока email не подтвержден (кроме админа)
    if not user.is_email_verified and user.role != "admin":
        flash("⚠ Подтвердите email, чтобы оформить заказ. Можно нажать «Отправить письмо повторно».", "warning")
        return redirect(url_for("profile"))

    items = CartItem.query.filter_by(user_id=user.id).all()
    if not items:
        flash("Корзина пуста.", "warning")
        return redirect(url_for("cart"))

    total = sum(item.product.price * item.quantity for item in items)

    order = Order(user_id=user.id, status="new", confirmed=False)
    db.session.add(order)
    db.session.flush()

    for item in items:
        order_item = OrderItem(
            order_id=order.id,
            product_id=item.product_id,
            quantity=item.quantity
        )
        db.session.add(order_item)
        db.session.delete(item)

    db.session.commit()

    # Telegram уведомление
    lines = []
    lines.append(f"🛒 <b>Новый заказ #{order.id}</b>")
    lines.append("")
    lines.append(f"<b>Пользователь:</b> {user.full_name()}")
    lines.append(f"<b>Email:</b> {user.email}")
    lines.append(f"<b>Город:</b> {user.city}")
    lines.append(f"<b>ID:</b> <code>{user.public_id}</code>")
    lines.append("")
    lines.append("<b>Состав заказа:</b>")

    for oi in order.items:
        line_sum = oi.product.price * oi.quantity
        lines.append(f"- {oi.product.name} — {oi.quantity} шт. × {oi.product.price} ₸ = {line_sum} ₸")

    lines.append("")
    lines.append(f"<b>Итого:</b> {total} ₸")
    lines.append("")
    lines.append(f"<b>Статус:</b> new (новый)")
    lines.append(f"<b>Подтверждён админом:</b> нет")

    send_telegram_message("\n".join(lines))

    flash("Заказ успешно оформлен!", "success")
    return redirect(url_for("profile"))


# -----------------------------------
#          ЛИЧНЫЙ КАБИНЕТ
# -----------------------------------

@app.route("/profile")
@login_required
def profile():
    user = get_current_user()
    orders = Order.query.filter_by(user_id=user.id).all()
    return render_template("profile.html", user=user, orders=orders)


@app.route("/profile/edit", methods=["GET", "POST"])
@login_required
def profile_edit():
    user = get_current_user()

    if request.method == "POST":
        last_name = request.form.get("last_name", "").strip()
        first_name = request.form.get("first_name", "").strip()
        middle_name = request.form.get("middle_name", "").strip()
        city = request.form.get("city", "").strip()
        phone = request.form.get("phone", "").strip()

        errors = []

        if not last_name or not is_valid_name(last_name):
            errors.append("Фамилия обязательна и может содержать только буквы, пробел и дефис.")
        if not first_name or not is_valid_name(first_name):
            errors.append("Имя обязательно и может содержать только буквы, пробел и дефис.")
        if not middle_name or not is_valid_name(middle_name):
            errors.append("Отчество обязательно и может содержать только буквы, пробел и дефис.")
        if not city or city not in CITIES:
            errors.append("Выберите город из списка.")
        if not phone or not is_valid_kz_phone(phone):
            errors.append("Номер телефона должен быть в формате +7XXXXXXXXXX (Казахстан).")

        avatar_file = request.files.get("avatar")
        avatar_filename = None

        if avatar_file and avatar_file.filename:
            if allowed_file(avatar_file.filename):
                safe_name = secure_filename(avatar_file.filename)
                save_path = os.path.join(AVATAR_FOLDER, safe_name)
                avatar_file.save(save_path)
                avatar_filename = f"uploads/avatars/{safe_name}"
            else:
                errors.append("Недопустимый формат файла аватара. Разрешены png, jpg, jpeg, gif.")

        if errors:
            for e in errors:
                flash(e, "danger")
            return render_template("profile_edit.html", user=user)

        user.last_name = last_name
        user.first_name = first_name
        user.middle_name = middle_name
        user.city = city
        user.phone = phone
        if avatar_filename:
            user.avatar_image = avatar_filename

        db.session.commit()
        flash("Профиль успешно обновлён.", "success")
        return redirect(url_for("profile"))

    return render_template("profile_edit.html", user=user)


# -----------------------------------
#           АДМИН-ПАНЕЛЬ
# -----------------------------------

@app.route("/admin")
@admin_required
def admin_panel():
    products = Product.query.all()
    users = User.query.all()
    orders = Order.query.order_by(Order.id.desc()).all()
    return render_template("admin.html", products=products, users=users, orders=orders)


@app.route("/admin/products/new", methods=["GET", "POST"])
@admin_required
def admin_add_product():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        description = request.form.get("description", "").strip()
        price_raw = request.form.get("price", "").strip()
        image_file = request.files.get("image")

        errors = []
        if not name:
            errors.append("Название товара обязательно.")
        if not description:
            errors.append("Описание товара обязательно.")
        if not price_raw.isdigit():
            errors.append("Цена должна быть числом (в тенге).")

        filename = None
        if image_file and image_file.filename:
            if allowed_file(image_file.filename):
                filename = secure_filename(image_file.filename)
                save_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
                image_file.save(save_path)
                filename = f"uploads/{filename}"
            else:
                errors.append("Недопустимый формат файла картинки.")

        if errors:
            for e in errors:
                flash(e, "danger")
            return render_template("admin_add_product.html")

        product = Product(
            name=name,
            description=description,
            price=int(price_raw),
            image=filename or None,
        )
        db.session.add(product)
        db.session.commit()

        flash("Товар успешно добавлен.", "success")
        return redirect(url_for("admin_panel"))

    return render_template("admin_add_product.html")


@app.route("/admin/products/<int:product_id>/delete", methods=["POST"])
@admin_required
def admin_delete_product(product_id):
    product = Product.query.get_or_404(product_id)

    from_order = OrderItem.query.filter_by(product_id=product.id).first()
    if from_order:
        flash("Нельзя удалить товар, который уже есть в оформленных заказах.", "danger")
        return redirect(url_for("admin_panel"))

    CartItem.query.filter_by(product_id=product.id).delete()

    db.session.delete(product)
    db.session.commit()
    flash("Товар удалён.", "info")
    return redirect(url_for("admin_panel"))


@app.route("/admin/users/<int:user_id>/toggle_block", methods=["POST"])
@admin_required
def admin_toggle_block(user_id):
    user = User.query.get_or_404(user_id)

    if user.role == "admin":
        flash("Нельзя блокировать администратора.", "danger")
        return redirect(url_for("admin_panel"))

    user.is_blocked = not user.is_blocked
    db.session.commit()

    if user.is_blocked:
        flash(f"Пользователь {user.email} заблокирован.", "warning")
    else:
        flash(f"Пользователь {user.email} разблокирован.", "success")

    return redirect(url_for("admin_panel"))


@app.route("/admin/orders/<int:order_id>/update", methods=["POST"])
@admin_required
def admin_update_order(order_id):
    order = Order.query.get_or_404(order_id)

    status = request.form.get("status", "new")
    confirmed = request.form.get("confirmed") == "on"

    if status not in ("new", "in_progress", "completed"):
        flash("Недопустимый статус.", "danger")
        return redirect(url_for("admin_panel"))

    order.status = status
    order.confirmed = confirmed
    db.session.commit()

    flash(f"Заказ #{order.id} обновлён.", "success")
    return redirect(url_for("admin_panel"))


@app.route("/admin/orders/<int:order_id>/delete", methods=["POST"])
@admin_required
def admin_delete_order(order_id):
    order = Order.query.get_or_404(order_id)

    # сначала удаляем позиции заказа
    OrderItem.query.filter_by(order_id=order.id).delete()

    # затем сам заказ
    db.session.delete(order)
    db.session.commit()

    flash(f"Заказ #{order.id} удалён.", "info")
    return redirect(url_for("admin_panel"))


# -----------------------------------
#          ТОЧКА ВХОДА
# -----------------------------------

if __name__ == "__main__":
    # для локалки можно один раз создать таблицы:
    # with app.app_context(): db.create_all()
    app.run(debug=True)
