"""
Sesión local firmada (HMAC-SHA256) para gate de Google Workspace.
Replica el comportamiento de lib/auth.ts del dashboard Next.js.

Cookie: 'vurelo-auth' · firmada · TTL 24h · payload base64url JSON.
"""
import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from functools import wraps

from flask import request, jsonify, redirect, url_for

AUTH_COOKIE_NAME = "vurelo-auth"
AUTH_TTL_SECONDS = 24 * 60 * 60
TTL_MS = AUTH_TTL_SECONDS * 1000

# AUTH_SECRET · prefer env · sino file persistido (~/.vurelo-auth-secret) auto-generado
_SECRET_FILE = os.path.expanduser("~/.vurelo-auth-secret")


def _load_or_create_secret() -> str:
    env = os.environ.get("AUTH_SECRET", "").strip()
    if env:
        return env
    if os.path.exists(_SECRET_FILE):
        try:
            with open(_SECRET_FILE) as f:
                v = f.read().strip()
                if v:
                    return v
        except Exception:
            pass
    # Generar nuevo
    s = secrets.token_hex(32)
    try:
        with open(_SECRET_FILE, "w") as f:
            f.write(s)
        os.chmod(_SECRET_FILE, 0o600)
    except Exception:
        pass
    return s


SECRET = _load_or_create_secret()


# ============ HMAC + base64url helpers ============

def _b64url_encode_bytes(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _b64url_encode_str(s: str) -> str:
    return _b64url_encode_bytes(s.encode("utf-8"))


def _b64url_decode_to_str(s: str) -> str:
    pad = "=" * ((-len(s)) % 4)
    return base64.urlsafe_b64decode(s + pad).decode("utf-8")


def _hmac_hex(payload: str) -> str:
    return hmac.new(SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()


# ============ Session sign/verify ============

def sign_session(payload: dict) -> str:
    """payload · {email, name?, picture?, sub?}. Retorna cookie string."""
    exp = int(time.time() * 1000) + TTL_MS
    body = _b64url_encode_str(json.dumps(payload, separators=(",", ":")))
    sig = _hmac_hex(f"{exp}.{body}")
    return f"{exp}.{body}.{sig}"


def verify_session(token: str) -> dict | None:
    """Retorna payload dict si OK · None si inválido/expirado/manipulado."""
    if not token:
        return None
    parts = token.split(".")
    if len(parts) != 3:
        return None
    exp_s, body, sig = parts
    try:
        exp = int(exp_s)
    except ValueError:
        return None
    if exp < int(time.time() * 1000):
        return None  # expirado
    expected = _hmac_hex(f"{exp_s}.{body}")
    if not hmac.compare_digest(sig, expected):
        return None  # firma inválida o manipulada
    try:
        decoded = json.loads(_b64url_decode_to_str(body))
        if not isinstance(decoded, dict) or "email" not in decoded:
            return None
        return decoded
    except Exception:
        return None


# ============ Flask helpers ============

def get_current_user() -> dict | None:
    """Lee la cookie del request actual · retorna payload o None."""
    token = request.cookies.get(AUTH_COOKIE_NAME)
    return verify_session(token)


# Paths exentos del gate · siempre permitidos
EXEMPT_PREFIXES = (
    "/login",
    "/api/auth/",
    "/static/",
    "/favicon",
)


def is_exempt(path: str) -> bool:
    return any(path.startswith(p) for p in EXEMPT_PREFIXES)


def require_auth():
    """
    Hook para usar en before_request del Flask app.
    Bloquea TODO endpoint que no esté en EXEMPT_PREFIXES.
    · API routes → JSON 401 · excepto /api/ops/* que aceptan x-api-key
    · Pages → redirect /login?next=<path>
    """
    if is_exempt(request.path):
        return None
    # 2026-05-29 · service-to-service · endpoints /api/ops/* aceptan x-api-key
    if request.path.startswith("/api/ops/"):
        provided = request.headers.get("x-api-key", "")
        expected = os.environ.get("VURELO_SERVICE_API_KEY", "")
        if expected and provided and hmac.compare_digest(provided, expected):
            return None
    user = get_current_user()
    if user:
        return None
    if request.path.startswith("/api/"):
        return jsonify({"error": "unauthorized", "message": "Google login requerido"}), 401
    # Redirect a login page
    next_url = request.path
    if request.query_string:
        next_url += "?" + request.query_string.decode()
    return redirect(f"/login?next={next_url}")
