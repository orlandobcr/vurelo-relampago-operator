"""
Cliente Relampago Pay API · login + keep-alive automático.

Flow descubierto vía reverse engineering 2026-05-22:
   1. Login Cognito Hosted UI · email + password
   2. MFA TOTP · PIN 6 dígitos
   3. POST /v0/auth/exchange con authorizationCode → access_token cookie
   4. Refresh cada ~9 min · POST /v0/auth/refresh con body {} y cookies

Cookies:
   · access_token  · Max-Age 600 (10 min) · rotated cada refresh
   · session_id    · Max-Age 3600 (60 min) · rotated cada refresh
"""
import re
import threading
import time
import json
from urllib.parse import urlparse, parse_qs

import requests

try:
    import storage
except ImportError:
    storage = None  # optional in tests


CLIENT_ID = "22349hus625pj1n8fro75672na"
REDIRECT_URI = "https://portal.relampago-pay.io/auth/callback"
API_BASE = "https://api.relampago-pay.io/v0"
AUTH_BASE = "https://auth.relampago-pay.io"
ORIGIN = "https://portal.relampago-pay.io"


class RelampagoSession:
    """Sesión persistente con refresh automático en background."""

    # Constants
    TOKEN_LIFETIME_S = 600        # 10 min · access_token Max-Age
    REFRESH_LEAD_S = 60           # intentar refresh 60s antes del expire
    REFRESH_RETRY_S = 30          # si "not ready" · reintentar en 30s

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Macintosh) AppleWebKit/537.36",
            "Origin": ORIGIN,
            "Referer": f"{ORIGIN}/",
            "Accept": "application/json, text/plain, */*",
        })
        self._refresh_thread = None
        self._refresh_stop = threading.Event()
        self._logged_in = False
        self._last_refresh = None             # timestamp last successful refresh/exchange
        self._token_expires_at = None         # epoch · cuándo expira access_token
        self._last_login_email = None
        self._lock = threading.Lock()
        self._refresh_count = 0
        self._refresh_errors = 0
        self._consecutive_errors = 0

    # ============ State helpers ============

    @property
    def is_logged_in(self) -> bool:
        return self._logged_in and "access_token" in self.session.cookies

    @property
    def cookies_summary(self) -> dict:
        return {
            c.name: f"{c.value[:25]}... ({len(c.value)} chars)"
            for c in self.session.cookies
        }

    @property
    def status(self) -> dict:
        seconds_to_expire = None
        if self._token_expires_at:
            seconds_to_expire = max(0, int(self._token_expires_at - time.time()))
        return {
            "logged_in": self.is_logged_in,
            "email": self._last_login_email,
            "last_refresh": self._last_refresh,
            "last_refresh_iso": time.strftime("%H:%M:%S", time.localtime(self._last_refresh)) if self._last_refresh else None,
            "token_expires_at": self._token_expires_at,
            "token_expires_in_seconds": seconds_to_expire,
            "refresh_running": self._refresh_thread is not None and self._refresh_thread.is_alive(),
            "refresh_count": self._refresh_count,
            "refresh_errors": self._refresh_errors,
            "cookies": [c.name for c in self.session.cookies],
        }

    # ============ Login flow · 3 pasos ============

    def login_password(self, email: str, password: str) -> dict:
        """
        Paso 1 · POST username + password al Cognito Hosted UI.
        Retorna · {ok, next_step, message}
        Si OK · prepara internamente el state para el siguiente paso (MFA).
        """
        login_url = (
            f"{AUTH_BASE}/login?client_id={CLIENT_ID}&response_type=code"
            f"&scope=email+openid+profile&redirect_uri={REDIRECT_URI}"
        )

        # Reset cookies prev
        self.session.cookies.clear()

        try:
            r = self.session.get(login_url, timeout=10)
            csrf_m = re.search(r'name="csrf" value="([^"]+)"', r.text)
            if not csrf_m:
                return {"ok": False, "error": "no_csrf_token", "message": "No se encontró CSRF en login page"}
            csrf = csrf_m.group(1)
        except Exception as e:
            return {"ok": False, "error": "network_error", "message": f"GET login page falló · {e}"}

        try:
            r2 = self.session.post(
                login_url,
                data={
                    "csrf": csrf,
                    "username": email,
                    "password": password,
                    "cognitoAsfData": "",
                },
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Origin": AUTH_BASE,
                    "Referer": login_url,
                },
                allow_redirects=False,
                timeout=10,
            )
        except Exception as e:
            return {"ok": False, "error": "network_error", "message": f"POST login falló · {e}"}

        location = r2.headers.get("location", "")
        if r2.status_code != 302:
            return {
                "ok": False,
                "error": "invalid_credentials",
                "message": "Email o password incorrectos · o cuenta bloqueada",
                "status": r2.status_code,
            }

        if "/mfa/totp" in location:
            self._mfa_url = AUTH_BASE + location
            self._pending_email = email
            return {"ok": True, "next_step": "mfa_totp", "message": "Login OK · ingresa PIN TOTP"}

        # otros tipos de challenge no MFA
        return {
            "ok": False,
            "error": "unexpected_redirect",
            "message": f"Redirect inesperado · {location[:200]}",
        }

    def login_mfa(self, pin: str) -> dict:
        """
        Paso 2 · POST PIN TOTP al MFA endpoint.
        Si OK · captura el authorization code y lo intercambia por access_token.
        Retorna · {ok, message, balance? }
        """
        if not hasattr(self, "_mfa_url") or not self._mfa_url:
            return {"ok": False, "error": "no_pending_mfa", "message": "No hay login en progreso"}

        try:
            r3 = self.session.get(self._mfa_url, timeout=10)
            csrf_m = re.search(r'name="csrf" value="([^"]+)"', r3.text)
            if not csrf_m:
                return {"ok": False, "error": "no_csrf_mfa", "message": "No CSRF en MFA page"}
            csrf2 = csrf_m.group(1)
        except Exception as e:
            return {"ok": False, "error": "network_error", "message": str(e)}

        try:
            r4 = self.session.post(
                self._mfa_url,
                data={"csrf": csrf2, "code": pin, "cognitoAsfData": ""},
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Origin": AUTH_BASE,
                    "Referer": self._mfa_url,
                },
                allow_redirects=False,
                timeout=10,
            )
        except Exception as e:
            return {"ok": False, "error": "network_error", "message": str(e)}

        location = r4.headers.get("location", "")
        if r4.status_code != 302 or "code=" not in location:
            return {
                "ok": False,
                "error": "invalid_mfa",
                "message": "PIN incorrecto · expirado · o el code TOTP cambió. Reintentar con PIN fresco.",
                "status": r4.status_code,
            }

        qs = parse_qs(urlparse(location).query)
        code = (qs.get("code") or [None])[0]
        if not code:
            return {"ok": False, "error": "no_code", "message": "No authorization code en redirect"}

        # Paso 3 · exchange
        try:
            r5 = self.session.post(
                f"{API_BASE}/auth/exchange",
                json={"authorizationCode": code},
                headers={"Content-Type": "application/json"},
                timeout=15,
            )
        except Exception as e:
            return {"ok": False, "error": "network_error", "message": str(e)}

        if r5.status_code != 200:
            return {
                "ok": False,
                "error": "exchange_failed",
                "message": f"Exchange code falló · HTTP {r5.status_code} · {r5.text[:200]}",
            }

        # Verificar access_token cookie
        if "access_token" not in self.session.cookies:
            return {"ok": False, "error": "no_access_token", "message": "Exchange OK pero NO se seteó access_token cookie"}

        self._logged_in = True
        self._last_login_email = self._pending_email
        expires_in = int(r5.json().get("data", {}).get("expiresIn", self.TOKEN_LIFETIME_S))
        self._last_refresh = time.time()
        self._token_expires_at = time.time() + expires_in
        self._mfa_url = None
        self._pending_email = None
        self._consecutive_errors = 0

        # Persistir sesión inmediatamente · sobrevive restart
        self.persist_to_storage()

        # Arrancar refresh loop en background
        self._start_refresh_loop()

        return {
            "ok": True,
            "message": "Login completo · sesión activa",
            "expires_in_seconds": expires_in,
            "token_expires_at": self._token_expires_at,
        }

    # ============ Refresh loop ============

    def _start_refresh_loop(self):
        if self._refresh_thread and self._refresh_thread.is_alive():
            return
        self._refresh_stop.clear()
        self._refresh_thread = threading.Thread(target=self._refresh_loop, daemon=True, name="relampago-refresh")
        self._refresh_thread.start()

    def _refresh_loop(self):
        """
        Monitor continuo del token · refresh JUSTO antes de que expire.
        Estrategia:
          1. PRIMER check INMEDIATO (sin esperar el intervalo · cubre post-startup)
          2. Sleep 15s entre checks
          3. Si quedan <= REFRESH_LEAD_S (60s) · intentar refresh
          4. Si server dice "not ready" · esperar REFRESH_RETRY_S y reintentar
          5. Si todavía no ready y quedan <30s · loop frenético cada 10s
          6. Si expira o 401 · marcar logged_out · stop loop
        """
        CHECK_INTERVAL = 15  # cada 15s · más resolución (era 30s)
        first_iteration = True
        while not self._refresh_stop.is_set():
            # Primer check sin esperar (cubre el caso post-startup que el token esté cerca expire)
            if not first_iteration:
                if self._refresh_stop.wait(CHECK_INTERVAL):
                    break
            first_iteration = False
            if not self._logged_in:
                break
            if not self._token_expires_at:
                continue

            seconds_remaining = self._token_expires_at - time.time()

            # Token expirado · sesión perdida (algo falló)
            if seconds_remaining <= 0:
                self._logged_in = False
                self._refresh_errors += 1
                break

            # Refresh window · quedan <= LEAD seconds · intentar
            if seconds_remaining <= self.REFRESH_LEAD_S:
                ok = self._do_refresh()
                if ok:
                    continue  # Token renovado · seguir monitor
                # No ready o error · retry shortly
                # Si quedan <30s · loop más rápido
                retry_in = min(self.REFRESH_RETRY_S, max(5, int(seconds_remaining) // 2))
                if self._refresh_stop.wait(retry_in):
                    break
                ok2 = self._do_refresh()
                if not ok2 and (self._token_expires_at - time.time()) <= 10:
                    # Crítico · token a 10s de expirar y refresh sigue fallando
                    # Marcar sesión perdida · UI deberá re-login
                    self._logged_in = False
                    self._refresh_errors += 1
                    break

    def _do_refresh(self) -> bool:
        """
        Ejecuta UN intento de refresh.
        True · refresh OK · cookies rotated · _token_expires_at actualizado
        False · server dijo "not ready" · 4xx · o network error
        """
        with self._lock:
            try:
                r = self.session.post(
                    f"{API_BASE}/auth/refresh",
                    json={},
                    headers={"Content-Type": "application/json"},
                    timeout=10,
                )
            except Exception:
                self._refresh_errors += 1
                return False

            if r.status_code == 200:
                # Cookies access_token + session_id ya están en self.session.cookies
                self._last_refresh = time.time()
                expires_in = self.TOKEN_LIFETIME_S
                try:
                    body = r.json()
                    expires_in = int(body.get("data", {}).get("expiresIn", expires_in))
                except Exception:
                    pass
                self._token_expires_at = time.time() + expires_in
                self._refresh_count += 1
                self._consecutive_errors = 0
                # Persist actualizado a SQLite · sobrevive restarts
                self.persist_to_storage()
                return True
            if r.status_code == 400:
                # "Token not ready for refresh" · normal · esperar y retry
                return False
            if r.status_code in (401, 403):
                self._logged_in = False
                self._refresh_errors += 1
                self._consecutive_errors += 1
                if storage is not None:
                    try:
                        storage.clear_session()
                    except Exception:
                        pass
                return False
            self._refresh_errors += 1
            self._consecutive_errors += 1
            return False

    def force_refresh(self) -> dict:
        """Forzar un refresh manual (para UI)."""
        ok = self._do_refresh()
        return {"ok": ok, "last_refresh": self._last_refresh, "logged_in": self.is_logged_in}

    # ============ Persistence ============

    def persist_to_storage(self):
        """Guarda cookies + meta en SQLite (storage.session_state)."""
        if storage is None or not self._logged_in:
            return
        try:
            cookies_dict = {
                c.name: {"value": c.value, "domain": c.domain, "path": c.path}
                for c in self.session.cookies
            }
            storage.save_session(
                cookies=cookies_dict,
                email=self._last_login_email or "",
                last_refresh=self._last_refresh or 0,
                token_expires_at=self._token_expires_at or 0,
                refresh_count=self._refresh_count,
            )
        except Exception:
            pass

    def restore_from_storage(self) -> bool:
        """
        Intenta cargar sesión persistida de SQLite.
        Returns True si encontró cookies · y la sesión PARECE viva.
        El caller debe llamar verify_session_alive() después.
        """
        if storage is None:
            return False
        try:
            data = storage.load_session()
            if not data or not data.get("cookies"):
                return False
            # Load cookies a self.session
            for name, info in data["cookies"].items():
                self.session.cookies.set(
                    name,
                    info["value"],
                    domain=info.get("domain"),
                    path=info.get("path", "/"),
                )
            self._last_login_email = data.get("email")
            self._last_refresh = data.get("last_refresh")
            self._token_expires_at = data.get("token_expires_at")
            self._refresh_count = data.get("refresh_count", 0)
            return True
        except Exception:
            return False

    def verify_session_alive(self) -> bool:
        """
        Hace un health-check rápido a /account/balance.
        Si 200 · sesión viva · marca logged_in y arranca refresh loop.
        Si 401/403 · sesión muerta · clear cookies.

        IMPORTANTE: si el token tiene <= 2*LEAD seconds de vida (120s default),
        forzamos un refresh INMEDIATO antes de retornar · esto evita el gap
        post-redeploy donde el container arranca con token casi expirado y el
        loop normal (que espera 30s entre checks) no alcanza a refrescar.
        """
        if "access_token" not in self.session.cookies:
            return False
        try:
            r = self.session.get(f"{API_BASE}/account/balance", timeout=8)
            if r.status_code == 200:
                self._logged_in = True
                if not self._token_expires_at:
                    self._token_expires_at = time.time() + self.TOKEN_LIFETIME_S

                # Refresh INMEDIATO si quedan <= 2*LEAD (default 120s)
                # Cubre el caso post-redeploy · token podría estar cerca del expire
                remaining = self._token_expires_at - time.time()
                if remaining <= (2 * self.REFRESH_LEAD_S):
                    print(f"⚡ Token quedan {int(remaining)}s · forzando refresh inmediato post-startup")
                    self._do_refresh()  # síncrono · no esperamos al loop

                self._start_refresh_loop()
                return True
            elif r.status_code in (401, 403):
                # Sesión muerta · limpiar
                self.session.cookies.clear()
                self._logged_in = False
                if storage is not None:
                    try:
                        storage.clear_session()
                    except Exception:
                        pass
                return False
            return False
        except Exception:
            return False

    def logout(self):
        try:
            self.session.post(f"{API_BASE}/auth/logout", timeout=5)
        except Exception:
            pass
        self._refresh_stop.set()
        self.session.cookies.clear()
        self._logged_in = False
        self._last_login_email = None
        self._token_expires_at = None
        self._last_refresh = None
        if storage is not None:
            try:
                storage.clear_session()
            except Exception:
                pass

    # ============ API calls ============

    def get_balance(self) -> dict:
        if not self.is_logged_in:
            return {"ok": False, "error": "not_logged_in"}
        try:
            r = self.session.get(f"{API_BASE}/account/balance", timeout=10)
            if r.status_code == 200:
                return {"ok": True, "data": r.json().get("data", {})}
            return {"ok": False, "error": f"http_{r.status_code}", "body": r.text[:300]}
        except Exception as e:
            return {"ok": False, "error": "network_error", "message": str(e)}

    def get_bank_codes(self) -> dict:
        try:
            r = self.session.get(f"{API_BASE}/account/bank-codes", timeout=10)
            return {"ok": r.status_code == 200, "data": r.json().get("data") if r.status_code == 200 else None}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def get_transactions(self) -> dict:
        try:
            r = self.session.get(f"{API_BASE}/account/transactions", timeout=10)
            return {"ok": r.status_code == 200, "data": r.json().get("data") if r.status_code == 200 else None}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def resolve_payee(self, key: str, amount: int, routing: str = "breb") -> dict:
        """
        Valida si la llave existe · retorna info del payee si OK · 404 si inválida.
        """
        body = {
            "data": {
                "transfers": [{
                    "virtualAmount": int(amount),
                    "payee": {
                        "bank_account": {
                            "type": "",
                            "bank_code": "",
                            "bank_name": "",
                            "number": key,
                        },
                        "document_type": "",
                        "document_number": "",
                        "name": "",
                    },
                    "routing": routing,
                    "description": "Vurelo validation",
                    "emails_to_notify": [],
                    "reference": "",
                }]
            }
        }
        try:
            r = self.session.post(
                f"{API_BASE}/transactions/resolve-payee",
                json=body,
                headers={"Content-Type": "application/json"},
                timeout=15,
            )
            return {
                "ok": r.status_code == 200,
                "status": r.status_code,
                "data": r.json() if r.text else None,
            }
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def execute_dispersion(self, transfers: list) -> dict:
        """
        Ejecutar dispersión REAL.
        Relampago retorna HTTP 201 Created cuando OK · NO 200.
        """
        body = {"data": {"transfers": transfers}}
        try:
            r = self.session.post(
                f"{API_BASE}/transactions/execute",
                json=body,
                headers={"Content-Type": "application/json"},
                timeout=30,
            )
            return {
                "ok": 200 <= r.status_code < 300,  # FIX · 201 también OK (Created)
                "status": r.status_code,
                "data": r.json() if r.text else None,
            }
        except Exception as e:
            return {"ok": False, "error": str(e)}
