"""
Google OAuth 2.0 · Authorization Code flow + id_token verification.
Replica el comportamiento del dashboard Next.js (lib/google-oauth.ts).

Gate de dominio · solo cuentas @vureloapp.com (configurable via env).

Endpoints estándar:
   AUTH:    https://accounts.google.com/o/oauth2/v2/auth
   TOKEN:   https://oauth2.googleapis.com/token
   JWKS:    https://www.googleapis.com/oauth2/v3/certs
"""
import base64
import json
import os
import time
from urllib.parse import urlencode

import requests
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.exceptions import InvalidSignature


# ============ Config (mismo OAuth client que el dashboard) ============
# Project · vurelo-app-production · OAuth client "Vurelo Dashboard · backoffice compliance"
CLIENT_ID = os.environ.get(
    "GOOGLE_CLIENT_ID",
    "638758571049-ik8h2ri7fujld1rduu6pgjgmc8v6bgds.apps.googleusercontent.com",
)
CLIENT_SECRET = os.environ.get(
    "GOOGLE_CLIENT_SECRET",
    "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",
)
REQUIRED_HD = os.environ.get("GOOGLE_REQUIRED_HD", "vureloapp.com")
REQUIRED_EMAIL_SUFFIX = f"@{REQUIRED_HD}"

AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs"

_jwks_cache = {"keys": None, "expires": 0}


def is_configured() -> bool:
    return bool(CLIENT_ID and CLIENT_SECRET)


def build_auth_url(redirect_uri: str, state: str) -> str:
    if not CLIENT_ID:
        raise RuntimeError("GOOGLE_CLIENT_ID not configured")
    params = {
        "client_id": CLIENT_ID,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "online",
        "prompt": "select_account",
        "hd": REQUIRED_HD,
        "state": state,
    }
    return f"{AUTH_URL}?{urlencode(params)}"


def exchange_code(code: str, redirect_uri: str) -> dict:
    """Cambia auth code por tokens."""
    body = {
        "code": code,
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "redirect_uri": redirect_uri,
        "grant_type": "authorization_code",
    }
    r = requests.post(
        TOKEN_URL,
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=10,
    )
    if not r.ok:
        raise RuntimeError(f"Google token exchange {r.status_code} · {r.text[:300]}")
    return r.json()


def _b64url_decode(s: str) -> bytes:
    pad = "=" * ((-len(s)) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _fetch_jwks() -> list:
    now = time.time()
    if _jwks_cache["keys"] and _jwks_cache["expires"] > now:
        return _jwks_cache["keys"]
    r = requests.get(JWKS_URL, timeout=10)
    if not r.ok:
        raise RuntimeError(f"JWKS fetch {r.status_code}")
    data = r.json()
    _jwks_cache["keys"] = data["keys"]
    _jwks_cache["expires"] = now + 3600  # 1h cache
    return data["keys"]


def _verify_rs256_signature(id_token: str) -> tuple[dict, dict]:
    """Verifica firma RS256 contra JWKS · retorna (header, payload)."""
    parts = id_token.split(".")
    if len(parts) != 3:
        raise RuntimeError("id_token formato inválido")
    header_b64, payload_b64, sig_b64 = parts

    header = json.loads(_b64url_decode(header_b64))
    payload = json.loads(_b64url_decode(payload_b64))

    keys = _fetch_jwks()
    jwk = next((k for k in keys if k["kid"] == header["kid"]), None)
    if not jwk:
        raise RuntimeError("JWKS key not found for kid")

    n = int.from_bytes(_b64url_decode(jwk["n"]), "big")
    e = int.from_bytes(_b64url_decode(jwk["e"]), "big")
    public_key = RSAPublicNumbers(e, n).public_key()
    signed = f"{header_b64}.{payload_b64}".encode()
    signature = _b64url_decode(sig_b64)
    try:
        public_key.verify(signature, signed, PKCS1v15(), SHA256())
    except InvalidSignature:
        raise RuntimeError("id_token firma inválida")

    return header, payload


def verify_id_token(id_token: str) -> dict:
    """
    Verifica id_token completo:
      - Firma RS256 vs JWKS
      - iss · aud · exp · email_verified
      - Gate de dominio @vureloapp.com (hd + email suffix)
    Retorna payload del id_token (dict).
    """
    if not CLIENT_ID:
        raise RuntimeError("GOOGLE_CLIENT_ID not configured")

    _, payload = _verify_rs256_signature(id_token)

    now = int(time.time())
    if payload.get("exp", 0) < now:
        raise RuntimeError("id_token expirado")
    if payload.get("aud") != CLIENT_ID:
        raise RuntimeError(f"aud inválido · {payload.get('aud')}")
    if payload.get("iss") not in ("accounts.google.com", "https://accounts.google.com"):
        raise RuntimeError(f"iss inválido · {payload.get('iss')}")
    if not payload.get("email_verified"):
        raise RuntimeError("email no verificado por Google")

    # Gate dominio
    email = (payload.get("email") or "").lower()
    is_vurelo = payload.get("hd") == REQUIRED_HD or email.endswith(REQUIRED_EMAIL_SUFFIX)
    if not is_vurelo:
        raise RuntimeError(
            f"dominio no autorizado · solo cuentas {REQUIRED_EMAIL_SUFFIX} (recibido · {email})"
        )

    return payload
