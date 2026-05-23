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

    # Constants · replica patrón frontend Relampago oficial (descubierto vía main.js):
    #    Frontend hace · UN solo timer · dispara 10s antes del expire · max 2 retries
    #    NO loop · NO polling · NO retry agresivo (evita saturar el server)
    TOKEN_LIFETIME_S = 600        # 10 min · access_token Max-Age
    REFRESH_LEAD_S = 10           # 10s antes del expire (igual al frontend Relampago)
    REFRESH_RETRY_S = 5           # si "not ready" · reintentar 5s después
    REFRESH_MAX_RETRIES = 3       # max 3 intentos · luego logout

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
        # Diagnostic 2026-05-23 · capturar patrón refresh
        self._refresh_history = []  # last 50 events · (ts_iso, status, cookies_rotated, expires_in)
        self._session_started_at = None  # epoch · cuando se hizo login_exchange
        self._cookie_access_token_value = None  # para detectar si rotó
        self._cookie_session_id_value = None

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

        # Diagnostic 2026-05-23 · session age + Cognito refresh_token age estimate
        session_age_hours = None
        session_age_days = None
        if self._session_started_at:
            session_age_s = time.time() - self._session_started_at
            session_age_hours = round(session_age_s / 3600, 2)
            session_age_days = round(session_age_s / 86400, 2)

        # Cognito refresh_token TTL default 30d · estimar tiempo restante
        cognito_refresh_token_days_left = None
        if self._session_started_at:
            elapsed_days = (time.time() - self._session_started_at) / 86400
            cognito_refresh_token_days_left = round(30 - elapsed_days, 2)

        return {
            "logged_in": self.is_logged_in,
            "email": self._last_login_email,
            "session_started_at": self._session_started_at,
            "session_started_iso": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self._session_started_at)) if self._session_started_at else None,
            "session_age_hours": session_age_hours,
            "session_age_days": session_age_days,
            "cognito_refresh_token_days_left": cognito_refresh_token_days_left,
            "last_refresh": self._last_refresh,
            "last_refresh_iso": time.strftime("%H:%M:%S", time.localtime(self._last_refresh)) if self._last_refresh else None,
            "token_expires_at": self._token_expires_at,
            "token_expires_in_seconds": seconds_to_expire,
            "refresh_running": self._refresh_thread is not None and self._refresh_thread.is_alive(),
            "refresh_count": self._refresh_count,
            "refresh_errors": self._refresh_errors,
            "consecutive_errors": self._consecutive_errors,
            "cookies": [c.name for c in self.session.cookies],
            # Diagnostic 2026-05-23 · ¿cookie rotó en último refresh?
            "cookie_access_token_last_chars": (self._cookie_access_token_value[-8:] if self._cookie_access_token_value else None),
            "cookie_session_id_last_chars": (self._cookie_session_id_value[-8:] if self._cookie_session_id_value else None),
        }

    @property
    def refresh_history(self) -> list:
        """Last 50 refresh events · for diagnostic /api/refresh-history endpoint."""
        return list(self._refresh_history)

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
        # Diagnostic 2026-05-23 · track Cognito refresh_token TTL (30d default)
        self._session_started_at = time.time()
        self._cookie_access_token_value = self.session.cookies.get("access_token")
        self._cookie_session_id_value = self.session.cookies.get("session_id")
        self._add_history({
            "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
            "status": "LOGIN_FRESH",
            "email": self._last_login_email,
            "expires_in": expires_in,
        })

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
        Refresh proactivo · replica patrón frontend Relampago oficial.
        Estrategia · UN solo timer absoluto · NO polling · NO retry agresivo:

          1. Calcular momento exacto de refresh · expire_at - 10s
          2. Sleep hasta ese momento (timer absoluto · NO loop check)
          3. Intentar refresh UNA vez
          4. Si OK · recalcular timer · esperar siguiente ciclo
          5. Si "not ready" · retry max 3 veces con 5s entre intentos
          6. Si todos fallan · logout (igual frontend oficial)

        Esto NO satura el server · genera 1 llamada cada ~10min (normal)
        o max 3 si hay reintentos · muy ligero footprint.
        """
        while not self._refresh_stop.is_set():
            if not self._logged_in or not self._token_expires_at:
                break

            # Calcular cuánto esperar · refresh a 10s antes del expire
            wait_until_refresh = self._token_expires_at - time.time() - self.REFRESH_LEAD_S

            if wait_until_refresh > 0:
                # Sleep hasta el momento exacto · NO loop checks
                if self._refresh_stop.wait(wait_until_refresh):
                    break
            # Si llegamos aquí · es hora de refresh

            # Intentar refresh · max REFRESH_MAX_RETRIES con espaciado RETRY_S
            success = False
            for attempt in range(1, self.REFRESH_MAX_RETRIES + 1):
                if self._refresh_stop.is_set():
                    return
                ok = self._do_refresh()
                if ok:
                    new_remaining = self._token_expires_at - time.time()
                    print(f"✓ Refresh OK · count={self._refresh_count} · nuevo token expira en {int(new_remaining)}s (attempt {attempt})")
                    success = True
                    break
                # Retry · esperar RETRY_S antes del próximo
                remaining = self._token_expires_at - time.time()
                if remaining <= 0:
                    print(f"⚠⚠⚠ Token expiró durante retries · sesión perdida")
                    break
                print(f"⚠ Refresh attempt {attempt}/{self.REFRESH_MAX_RETRIES} falló (token quedan {int(remaining)}s) · retry en {self.REFRESH_RETRY_S}s")
                if self._refresh_stop.wait(self.REFRESH_RETRY_S):
                    return

            if not success:
                # Todos los retries fallaron · logout (igual frontend Relampago)
                print(f"⚠⚠⚠ SESIÓN PERDIDA · {self.REFRESH_MAX_RETRIES} refresh attempts fallaron")
                self._logged_in = False
                self._refresh_errors += 1
                if storage is not None:
                    try:
                        storage.clear_session()
                    except Exception:
                        pass
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
            except Exception as e:
                self._refresh_errors += 1
                self._consecutive_errors += 1
                self._add_history({
                    "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "status": "NETWORK_ERROR",
                    "error": str(e)[:200],
                    "refresh_count": self._refresh_count,
                    "consecutive_errors": self._consecutive_errors,
                })
                return False

            ts_iso = time.strftime("%Y-%m-%d %H:%M:%S")
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

                # Diagnostic 2026-05-23 · detectar si cookies realmente rotaron
                new_access = self.session.cookies.get("access_token")
                new_session = self.session.cookies.get("session_id")
                access_rotated = new_access != self._cookie_access_token_value
                session_rotated = new_session != self._cookie_session_id_value
                self._cookie_access_token_value = new_access
                self._cookie_session_id_value = new_session

                self._add_history({
                    "ts": ts_iso,
                    "status": "OK",
                    "http_code": 200,
                    "expires_in": expires_in,
                    "refresh_count": self._refresh_count,
                    "access_token_rotated": access_rotated,
                    "session_id_rotated": session_rotated,
                })

                # Persist actualizado a SQLite · sobrevive restarts
                self.persist_to_storage()
                return True
            if r.status_code == 400:
                # "Token not ready for refresh" · normal · esperar y retry
                self._add_history({
                    "ts": ts_iso,
                    "status": "RETRY_NEEDED",
                    "http_code": 400,
                    "refresh_count": self._refresh_count,
                })
                return False
            if r.status_code in (401, 403):
                self._logged_in = False
                self._refresh_errors += 1
                self._consecutive_errors += 1
                self._add_history({
                    "ts": ts_iso,
                    "status": "REVOKED",
                    "http_code": r.status_code,
                    "refresh_count": self._refresh_count,
                    "consecutive_errors": self._consecutive_errors,
                })
                if storage is not None:
                    try:
                        storage.clear_session()
                    except Exception:
                        pass
                return False
            self._refresh_errors += 1
            self._consecutive_errors += 1
            self._add_history({
                "ts": ts_iso,
                "status": "OTHER_ERROR",
                "http_code": r.status_code,
                "refresh_count": self._refresh_count,
                "consecutive_errors": self._consecutive_errors,
            })
            return False

    def _add_history(self, event: dict) -> None:
        """Add to refresh_history · keep max 50 events."""
        self._refresh_history.append(event)
        if len(self._refresh_history) > 50:
            self._refresh_history = self._refresh_history[-50:]

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
