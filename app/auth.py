"""Маршрути автентифікації та навчальна SQLi-лабораторія.

Модуль навмисно не містить жодної конкатенації SQL-рядків. Уся робота з
базою delegated до app.database, де використовуються bound parameters.
"""

from __future__ import annotations

import hmac
import secrets
from functools import wraps
from sqlite3 import IntegrityError

from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from .auth_security import (
    hash_password,
    validate_email,
    validate_password,
    validate_username,
    verify_dummy,
    verify_password,
)
from .database import create_user, find_user_by_id, find_user_by_username

auth_bp = Blueprint("auth", __name__)


# ---------------------------------------------------------------------------
# CSRF-захист
# ---------------------------------------------------------------------------

def csrf_token() -> str:
    """Повертає CSRF-токен поточної сесії, створюючи його за потреби."""

    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


def _require_csrf() -> None:
    """Перевіряє приховане поле csrf_token у кожній POST-формі."""

    expected = session.get("_csrf_token", "")
    supplied = request.form.get("csrf_token", "")

    if not expected or not hmac.compare_digest(expected, supplied):
        abort(
            400,
            description="Недійсний CSRF-токен. Оновіть сторінку та спробуйте ще раз.",
        )


# ---------------------------------------------------------------------------
# Завантаження користувача та декоратори
# ---------------------------------------------------------------------------

@auth_bp.before_app_request
def load_logged_in_user() -> None:
    """Відновлює користувача з підписаної сесійної cookie."""

    if request.endpoint == "static":
        return

    user_id = session.get("user_id")
    g.user = find_user_by_id(user_id) if user_id else None


def login_required(view):
    """Дозволяє доступ лише автентифікованим користувачам."""

    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.get("user") is None:
            flash("Спочатку увійдіть у систему.", "warning")
            return redirect(url_for("auth.login"))
        return view(*args, **kwargs)

    return wrapped


@auth_bp.app_context_processor
def inject_template_globals() -> dict:
    """Робить CSRF-токен і поточного користувача доступними у шаблонах."""

    return {
        "csrf_token": csrf_token,
        "current_user": g.get("user"),
    }


# ---------------------------------------------------------------------------
# Сторінки
# ---------------------------------------------------------------------------

@auth_bp.get("/")
def index():
    """Кореневий маршрут веде до кабінету або до форми входу."""

    if g.get("user"):
        return redirect(url_for("auth.dashboard"))
    return redirect(url_for("auth.login"))


@auth_bp.route("/register", methods=("GET", "POST"))
def register():
    """Реєстрація нового користувача з серверною валідацією."""

    if g.get("user"):
        return redirect(url_for("auth.dashboard"))

    form = {"username": "", "email": ""}

    if request.method == "POST":
        _require_csrf()

        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        form = {"username": username, "email": email}

        errors = []
        errors.extend(validate_username(username))
        errors.extend(validate_email(email))
        errors.extend(validate_password(password))

        if password != confirm_password:
            errors.append("Паролі не збігаються.")

        if errors:
            for error in errors:
                flash(error, "error")
            return render_template("register.html", form=form), 400

        password_hash, salt = hash_password(
            password,
            rounds=current_app.config["BCRYPT_ROUNDS"],
        )

        try:
            create_user(username, email, password_hash, salt)
        except IntegrityError:
            flash("Користувач з таким ім'ям або email уже існує.", "error")
            return render_template("register.html", form=form), 409

        flash("Акаунт створено. Увійдіть із новими обліковими даними.", "success")
        return redirect(url_for("auth.login"))

    return render_template("register.html", form=form)


@auth_bp.route("/login", methods=("GET", "POST"))
def login():
    """Перевірка автентичності з єдиним повідомленням про помилку."""

    if g.get("user"):
        return redirect(url_for("auth.dashboard"))

    form = {"username": ""}

    if request.method == "POST":
        _require_csrf()

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        form = {"username": username}

        if not username or not password:
            flash("Введіть ім'я користувача та пароль.", "error")
            return render_template("login.html", form=form), 400

        user = find_user_by_username(username)
        rounds = current_app.config["BCRYPT_ROUNDS"]

        # Навіть для неіснуючого користувача виконуємо bcrypt-перевірку над
        # dummy-хешем, щоб не розкривати факт існування акаунта за часом.
        if user is None:
            verify_dummy(password, rounds=rounds)
            flash("Невірне ім'я користувача або пароль.", "error")
            return render_template("login.html", form=form), 401

        if not user["is_active"]:
            verify_dummy(password, rounds=rounds)
            flash("Невірне ім'я користувача або пароль.", "error")
            return render_template("login.html", form=form), 401

        if not verify_password(password, user["password_hash"]):
            flash("Невірне ім'я користувача або пароль.", "error")
            return render_template("login.html", form=form), 401

        # Захист від session fixation: повністю оновлюємо сесію після входу.
        session.clear()
        session["user_id"] = user["id"]
        session["_csrf_token"] = secrets.token_urlsafe(32)
        session.permanent = True

        flash(f"Вітаємо, {user['username']}! Сесію відкрито.", "success")
        return redirect(url_for("auth.dashboard"))

    return render_template("login.html", form=form)


@auth_bp.post("/logout")
def logout():
    """Завершує сесію. Вихід доступний лише через POST із CSRF-токеном."""

    _require_csrf()
    session.clear()
    flash("Сесію завершено. Доступ до сховища закрито.", "success")
    return redirect(url_for("auth.login"))


@auth_bp.get("/dashboard")
@login_required
def dashboard():
    """Особистий кабінет користувача."""

    return render_template("dashboard.html", user=g.user)


@auth_bp.route("/security-lab", methods=("GET", "POST"))
def security_lab():
    """Навчальна read-only перевірка стійкості до SQL-ін'єкцій.

    Форма виконує той самий параметризований SELECT, що й вхід, але не
    створює сесію та не повертає персональних даних. Це демонстраційний
    стенд для протоколу тестування.
    """

    payload = "' OR '1'='1"
    tested = False
    result = None

    if request.method == "POST":
        _require_csrf()
        payload = request.form.get("payload", "")
        if not payload:
            flash("Введіть payload для перевірки.", "warning")
        else:
            result = find_user_by_username(payload)
            tested = True

    return render_template(
        "security_lab.html",
        payload=payload,
        tested=tested,
        result=result,
    )


@auth_bp.get("/api-lab")
def api_lab():
    """Інтерактивний стенд для демонстрації JWT REST API (ЛР №2).

    Сторінка не використовує серверну сесію: усі запити до /api/v1/*
    виконуються з браузера через fetch і показують реальні HTTP-статуси.
    """

    return render_template("api_lab.html")


@auth_bp.get("/healthz")
def healthz():
    """Службовий endpoint для перевірки живості застосунку."""

    return jsonify(status="ok", service="secure-docvault", stage="v0.2-jwt-api")
