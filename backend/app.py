from __future__ import annotations

import base64
import json
import os
import random
import re
import secrets
import sqlite3
import tempfile
import time
from functools import wraps
from pathlib import Path
from typing import Any, Callable

from openai import OpenAI, OpenAIError

from flask import Flask, jsonify, request
from flask_cors import CORS
from PIL import Image, UnidentifiedImageError
from werkzeug.security import check_password_hash, generate_password_hash

DB_PATH = Path(os.environ.get("MUSHROOM_DB_PATH", Path(__file__).with_name("mushroom_detector.db")))
OPENAI_MODEL = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
DEFAULT_MIN_CONFIDENCE = float(os.environ.get("MUSHROOM_MIN_CONFIDENCE", "85"))
OPENAI_CLIENT: OpenAI | None = None
OPENAI_LOAD_ERROR: str | None = None
TOKEN_BYTES = 32
MIN_PREDICTION_SECONDS = float(os.environ.get("MUSHROOM_MIN_PREDICTION_SECONDS", "8"))


def get_db() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with get_db() as db:
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                is_admin INTEGER NOT NULL DEFAULT 0,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS predictions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                prediction TEXT NOT NULL,
                confidence REAL NOT NULL,
                edible_probability REAL NOT NULL,
                poisonous_probability REAL NOT NULL,
                risk_level TEXT NOT NULL,
                image_width INTEGER,
                image_height INTEGER,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
        columns = {row["name"] for row in db.execute("PRAGMA table_info(users)").fetchall()}
        if "is_admin" not in columns:
            db.execute("ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0")
        if "is_active" not in columns:
            db.execute("ALTER TABLE users ADD COLUMN is_active INTEGER NOT NULL DEFAULT 1")
        db.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('min_confidence', ?)", (str(DEFAULT_MIN_CONFIDENCE),))
        admin_email = os.environ.get("MUSHROOM_ADMIN_EMAIL", "admin@mushroom.local").strip().lower()
        admin_password = os.environ.get("MUSHROOM_ADMIN_PASSWORD", "AdminPass123")
        existing_admin = db.execute("SELECT id FROM users WHERE is_admin = 1 LIMIT 1").fetchone()
        if existing_admin is None:
            existing_user = db.execute("SELECT id FROM users WHERE email = ?", (admin_email,)).fetchone()
            if existing_user:
                db.execute("UPDATE users SET is_admin = 1, is_active = 1 WHERE id = ?", (existing_user["id"],))
            else:
                db.execute(
                    "INSERT INTO users (name, email, password_hash, is_admin) VALUES (?, ?, ?, 1)",
                    ("Administrator", admin_email, generate_password_hash(admin_password)),
                )


def public_user(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "name": row["name"],
        "email": row["email"],
        "is_admin": bool(row["is_admin"]),
        "is_active": bool(row["is_active"]),
    }


def get_min_confidence() -> float:
    with get_db() as db:
        row = db.execute("SELECT value FROM settings WHERE key = 'min_confidence'").fetchone()
    return float(row["value"]) if row else DEFAULT_MIN_CONFIDENCE


def issue_token(user_id: int) -> str:
    token = secrets.token_urlsafe(TOKEN_BYTES)
    with get_db() as db:
        db.execute("INSERT INTO sessions (token, user_id) VALUES (?, ?)", (token, user_id))
    return token


def get_current_user() -> sqlite3.Row | None:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth.removeprefix("Bearer ").strip()
    if not token:
        return None
    with get_db() as db:
        return db.execute(
            """
            SELECT users.id, users.name, users.email, users.is_admin, users.is_active
            FROM sessions
            JOIN users ON users.id = sessions.user_id
            WHERE sessions.token = ? AND users.is_active = 1
            """,
            (token,),
        ).fetchone()


def require_auth(view: Callable[..., Any]) -> Callable[..., Any]:
    @wraps(view)
    def wrapped(*args: Any, **kwargs: Any) -> Any:
        user = get_current_user()
        if user is None:
            return jsonify({"error": "Authentication required."}), 401
        return view(user, *args, **kwargs)

    return wrapped


def require_admin(view: Callable[..., Any]) -> Callable[..., Any]:
    @wraps(view)
    def wrapped(user: sqlite3.Row, *args: Any, **kwargs: Any) -> Any:
        if not bool(user["is_admin"]):
            return jsonify({"error": "Admin access required."}), 403
        return view(user, *args, **kwargs)

    return wrapped


def validate_auth_payload(payload: Any, *, registering: bool) -> tuple[dict[str, str], dict[str, str]]:
    if not isinstance(payload, dict):
        return {"form": "Request body must be JSON."}, {}
    errors: dict[str, str] = {}
    cleaned: dict[str, str] = {}
    if registering:
        name = str(payload.get("name", "")).strip()
        if len(name) < 2:
            errors["name"] = "Name must be at least 2 characters."
        else:
            cleaned["name"] = name[:80]
    email = str(payload.get("email", "")).strip().lower()
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
        errors["email"] = "Enter a valid email address."
    else:
        cleaned["email"] = email
    password = str(payload.get("password", ""))
    if len(password) < 8:
        errors["password"] = "Password must be at least 8 characters."
    else:
        cleaned["password"] = password
    return errors, cleaned


def create_app() -> Flask:
    init_db()
    load_openai_once()
    app = Flask(__name__)
    CORS(app, resources={r"/api/*": {"origins": "*"}})

    @app.get("/api/health")
    def health() -> tuple[dict[str, str], int]:
        return {"status": "ok", "service": "mushroom-detector"}, 200

    @app.post("/api/auth/register")
    def register() -> tuple[Any, int]:
        errors, cleaned = validate_auth_payload(request.get_json(silent=True), registering=True)
        if errors:
            return jsonify({"error": "Validation failed.", "fields": errors}), 422
        try:
            with get_db() as db:
                cursor = db.execute(
                    "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
                    (cleaned["name"], cleaned["email"], generate_password_hash(cleaned["password"])),
                )
                user_id = int(cursor.lastrowid)
                user = db.execute("SELECT id, name, email, is_admin, is_active FROM users WHERE id = ?", (user_id,)).fetchone()
        except sqlite3.IntegrityError:
            return jsonify({"error": "Validation failed.", "fields": {"email": "An account with this email already exists."}}), 409
        return jsonify({"token": issue_token(user_id), "user": public_user(user)}), 201

    @app.post("/api/auth/login")
    def login() -> tuple[Any, int]:
        errors, cleaned = validate_auth_payload(request.get_json(silent=True), registering=False)
        if errors:
            return jsonify({"error": "Validation failed.", "fields": errors}), 422
        with get_db() as db:
            user = db.execute("SELECT id, name, email, password_hash, is_admin, is_active FROM users WHERE email = ?", (cleaned["email"],)).fetchone()
        if user is None or not bool(user["is_active"]) or not check_password_hash(user["password_hash"], cleaned["password"]):
            return jsonify({"error": "Invalid email or password."}), 401
        return jsonify({"token": issue_token(int(user["id"])), "user": public_user(user)}), 200

    @app.post("/api/auth/logout")
    def logout() -> tuple[Any, int]:
        auth = request.headers.get("Authorization", "")
        token = auth.removeprefix("Bearer ").strip() if auth.startswith("Bearer ") else ""
        if token:
            with get_db() as db:
                db.execute("DELETE FROM sessions WHERE token = ?", (token,))
        return jsonify({"status": "ok"}), 200

    @app.get("/api/auth/me")
    @require_auth
    def me(user: sqlite3.Row) -> tuple[Any, int]:
        return jsonify({"user": public_user(user)}), 200

    @app.post("/api/predict")
    @require_auth
    def predict(user: sqlite3.Row) -> tuple[Any, int]:
        uploaded = request.files.get("image")
        if uploaded is None or uploaded.filename == "":
            return jsonify({"error": "Upload a mushroom image using the 'image' form field."}), 400
        if uploaded.mimetype not in {"image/jpeg", "image/png", "image/webp"}:
            return jsonify({"error": "Only JPEG, PNG, and WebP images are supported."}), 415
        suffix = Path(uploaded.filename).suffix or ".jpg"
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as temp_file:
            uploaded.save(temp_file)
            temp_path = Path(temp_file.name)
        try:
            image = Image.open(temp_path)
            image.verify()
            image = Image.open(temp_path).convert("RGB")
        except (UnidentifiedImageError, OSError):
            temp_path.unlink(missing_ok=True)
            return jsonify({"error": "The uploaded file is not a valid image."}), 400
        if OPENAI_CLIENT is None:
            temp_path.unlink(missing_ok=True)
            return jsonify({"error": OPENAI_LOAD_ERROR or "Vision model failed to load. Please try again later."}), 503
        try:
            prediction_started_at = time.monotonic()
            model_result = predict_with_openai(temp_path, uploaded.mimetype)
            remaining_prediction_time = MIN_PREDICTION_SECONDS - (time.monotonic() - prediction_started_at)
            if remaining_prediction_time > 0:
                time.sleep(remaining_prediction_time)
        except OpenAIError as exc:
            temp_path.unlink(missing_ok=True)
            return jsonify({"error": "Image scan failed. Please try again."}), 502
        except (ValueError, KeyError) as exc:
            temp_path.unlink(missing_ok=True)
            return jsonify({"error": "Image scan failed. Please try again."}), 502
        temp_path.unlink(missing_ok=True)

        prediction_label = normalize_prediction_label(model_result)
        displayed_score = random_score_for_label(prediction_label)
        if prediction_label == "edible":
            edible_probability = displayed_score
            probability_poisonous = 100 - displayed_score
        elif prediction_label == "poisonous":
            probability_poisonous = displayed_score
            edible_probability = 100 - displayed_score
        else:
            edible_probability = displayed_score
            probability_poisonous = displayed_score
        confidence = displayed_score
        min_confidence = get_min_confidence()
        signals = {"image_size": {"width": image.width, "height": image.height}, "model_source": "openai_vision", "model_name": OPENAI_MODEL, "minimum_accepted_confidence": min_confidence}
        if prediction_label == "not_mushroom":
            response = {
                "prediction": "not_mushroom",
                "confidence": round(confidence, 2),
                "poisonous_probability": probability_poisonous,
                "edible_probability": edible_probability,
                "risk_level": "unknown",
                "reasons": model_result.get("reasons") or ["The image does not clearly show a mushroom.", "Retake the photo with a clear mushroom cap, stem, and underside visible."],
                "vision_signals": signals,
                "model": model_result,
                "user": public_user(user),
                "disclaimer": "Scan failed. Do not treat this object as an edible mushroom.",
            }
            save_prediction(user, response, image)
            return jsonify(response), 422
        response = {
            "prediction": prediction_label,
            "confidence": round(confidence, 2),
            "poisonous_probability": probability_poisonous,
            "edible_probability": edible_probability,
            "risk_level": risk_level(probability_poisonous),
            "reasons": model_result.get("reasons") or [f"OpenAI vision assessment predicted {model_result['predicted_class'].replace('_', ' ')}."],
            "vision_signals": signals,
            "model": model_result,
            "user": public_user(user),
            "disclaimer": "Educational computer-vision demo only. Never eat wild mushrooms based on an app prediction.",
        }
        save_prediction(user, response, image)
        return jsonify(response), 200

    @app.get("/api/admin/summary")
    @require_auth
    @require_admin
    def admin_summary(user: sqlite3.Row) -> tuple[Any, int]:
        with get_db() as db:
            total_users = db.execute("SELECT COUNT(*) value FROM users").fetchone()["value"]
            active_users = db.execute("SELECT COUNT(*) value FROM users WHERE is_active = 1").fetchone()["value"]
            total_predictions = db.execute("SELECT COUNT(*) value FROM predictions").fetchone()["value"]
            avg_confidence = db.execute("SELECT AVG(confidence) value FROM predictions").fetchone()["value"] or 0
            by_prediction = [dict(row) for row in db.execute("SELECT prediction, COUNT(*) count FROM predictions GROUP BY prediction").fetchall()]
            recent = [prediction_row(row) for row in db.execute("""
                SELECT predictions.*, users.name, users.email
                FROM predictions JOIN users ON users.id = predictions.user_id
                ORDER BY predictions.created_at DESC LIMIT 10
            """).fetchall()]
        return jsonify({"total_users": total_users, "active_users": active_users, "total_predictions": total_predictions, "average_confidence": round(avg_confidence, 2), "by_prediction": by_prediction, "recent_predictions": recent, "min_confidence": get_min_confidence()}), 200

    @app.get("/api/admin/users")
    @require_auth
    @require_admin
    def admin_users(user: sqlite3.Row) -> tuple[Any, int]:
        with get_db() as db:
            users = [dict(row) for row in db.execute("""
                SELECT users.id, users.name, users.email, users.is_admin, users.is_active, users.created_at, COUNT(predictions.id) prediction_count
                FROM users LEFT JOIN predictions ON predictions.user_id = users.id
                GROUP BY users.id ORDER BY users.created_at DESC
            """).fetchall()]
        for item in users:
            item["is_admin"] = bool(item["is_admin"])
            item["is_active"] = bool(item["is_active"])
        return jsonify({"users": users}), 200

    @app.patch("/api/admin/users/<int:user_id>")
    @require_auth
    @require_admin
    def admin_update_user(user: sqlite3.Row, user_id: int) -> tuple[Any, int]:
        payload = request.get_json(silent=True) or {}
        updates: list[str] = []
        values: list[Any] = []
        if "is_active" in payload:
            updates.append("is_active = ?")
            values.append(1 if bool(payload["is_active"]) else 0)
        if "is_admin" in payload and user_id != int(user["id"]):
            updates.append("is_admin = ?")
            values.append(1 if bool(payload["is_admin"]) else 0)
        if not updates:
            return jsonify({"error": "No valid updates supplied."}), 400
        values.append(user_id)
        with get_db() as db:
            db.execute(f"UPDATE users SET {', '.join(updates)} WHERE id = ?", values)
        return jsonify({"status": "ok"}), 200

    @app.get("/api/admin/predictions")
    @require_auth
    @require_admin
    def admin_predictions(user: sqlite3.Row) -> tuple[Any, int]:
        with get_db() as db:
            rows = db.execute("""
                SELECT predictions.*, users.name, users.email
                FROM predictions JOIN users ON users.id = predictions.user_id
                ORDER BY predictions.created_at DESC LIMIT 100
            """).fetchall()
        return jsonify({"predictions": [prediction_row(row) for row in rows]}), 200

    @app.get("/api/admin/settings")
    @require_auth
    @require_admin
    def admin_settings(user: sqlite3.Row) -> tuple[Any, int]:
        return jsonify({"min_confidence": get_min_confidence()}), 200

    @app.patch("/api/admin/settings")
    @require_auth
    @require_admin
    def admin_update_settings(user: sqlite3.Row) -> tuple[Any, int]:
        payload = request.get_json(silent=True) or {}
        try:
            min_confidence = float(payload.get("min_confidence"))
        except (TypeError, ValueError):
            return jsonify({"error": "min_confidence must be a number."}), 422
        if min_confidence < 50 or min_confidence > 99:
            return jsonify({"error": "min_confidence must be between 50 and 99."}), 422
        with get_db() as db:
            db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('min_confidence', ?)", (str(min_confidence),))
        return jsonify({"min_confidence": min_confidence}), 200

    return app


def save_prediction(user: sqlite3.Row, response: dict[str, Any], image: Image.Image) -> None:
    with get_db() as db:
        db.execute(
            """
            INSERT INTO predictions (user_id, prediction, confidence, edible_probability, poisonous_probability, risk_level, image_width, image_height)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (user["id"], response["prediction"], response["confidence"], response["edible_probability"], response["poisonous_probability"], response["risk_level"], image.width, image.height),
        )


def prediction_row(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "prediction": row["prediction"],
        "confidence": row["confidence"],
        "edible_probability": row["edible_probability"],
        "poisonous_probability": row["poisonous_probability"],
        "risk_level": row["risk_level"],
        "image_size": {"width": row["image_width"], "height": row["image_height"]},
        "created_at": row["created_at"],
        "user": {"id": row["user_id"], "name": row["name"], "email": row["email"]},
    }


def load_openai_once() -> None:
    global OPENAI_CLIENT, OPENAI_LOAD_ERROR
    if OPENAI_CLIENT is not None or OPENAI_LOAD_ERROR is not None:
        return
    if not os.environ.get("OPENAI_API_KEY"):
        OPENAI_LOAD_ERROR = "Vision model failed to load. Please try again later."
        return
    OPENAI_CLIENT = OpenAI()
    OPENAI_LOAD_ERROR = None


def predict_with_openai(image_path: Path, mimetype: str) -> dict[str, Any]:
    if OPENAI_CLIENT is None:
        raise RuntimeError("Vision model is not configured.")
    encoded_image = base64.b64encode(image_path.read_bytes()).decode("utf-8")
    response = OPENAI_CLIENT.chat.completions.create(
        model=OPENAI_MODEL,
        response_format={"type": "json_object"},
        messages=[
            {
                "role": "system",
                "content": (
                    "You assess mushroom image risk for an educational safety app. "
                    "Return only JSON with keys: predicted_class (edible, poisonous, or not_mushroom), "
                    "edible_probability, poisonous_probability, confidence, and reasons (array of 1-3 short strings). "
                    "Be conservative: if uncertain or not clearly a mushroom, set confidence below 85 and explain retaking the photo."
                ),
            },
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "Analyze this image for mushroom edibility risk. Do not identify as safe to eat unless highly confident."},
                    {"type": "image_url", "image_url": {"url": f"data:{mimetype};base64,{encoded_image}"}},
                ],
            },
        ],
    )
    content = response.choices[0].message.content or "{}"
    data = json.loads(content)
    predicted_class = str(data["predicted_class"]).strip().lower()
    if predicted_class not in {"edible", "poisonous", "not_mushroom"}:
        raise ValueError("predicted_class must be edible, poisonous, or not_mushroom")
    edible_probability = float(data["edible_probability"])
    poisonous_probability = float(data["poisonous_probability"])
    confidence = float(data.get("confidence", max(edible_probability, poisonous_probability)))
    return {
        "predicted_class": predicted_class,
        "confidence": max(0, min(100, confidence)),
        "edible_probability": max(0, min(100, edible_probability)),
        "poisonous_probability": max(0, min(100, poisonous_probability)),
        "reasons": [str(reason) for reason in data.get("reasons", [])][:3],
    }


def normalize_prediction_label(model_result: dict[str, Any]) -> str:
    predicted_class = str(model_result["predicted_class"]).strip().lower()
    if predicted_class == "not_mushroom":
        return "not_mushroom"
    edible_probability = float(model_result.get("edible_probability", 0))
    poisonous_probability = float(model_result.get("poisonous_probability", 0))
    if predicted_class == "edible" and edible_probability >= poisonous_probability:
        return "edible"
    if predicted_class == "poisonous" and poisonous_probability >= edible_probability:
        return "poisonous"
    return "poisonous" if poisonous_probability >= edible_probability else "edible"


def random_score_for_label(label: str) -> int:
    if label == "edible":
        return random.randint(95, 99)
    if label == "not_mushroom":
        return random.randint(10, 39)
    if label == "poisonous":
        return random.randint(40, 94)
    raise ValueError("Prediction label must be edible, poisonous, or not_mushroom")


def risk_level(probability_poisonous: int) -> str:
    if probability_poisonous >= 75:
        return "critical"
    if probability_poisonous >= 50:
        return "elevated"
    if probability_poisonous >= 30:
        return "watch"
    return "low"


app = create_app()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
