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
        # ============ ARCHITECTURE FIX 2026-05-23 · dual session encapsulation ============
        # User principle · "TODA la lógica de refresh en el service · NO depender de UI"
        # Pre-fix · self.session (única) compartida entre refresh thread + 5 threads ops
        #          requests.Session NO thread-safe · race conditions · 36% fail rate.
        # Post-fix · 2 sessions internas:
        #   _session_auth · USADA SOLO por refresh thread + login (thread-isolated)
        #   _session_ops  · USADA por TODOS los ops (queries · dispersions · balance)
        #                   cookies sync'd atomic desde _session_auth post-refresh OK
        # Lock UNIVERSAL en TODOS los métodos públicos para serializar acceso.
        # `self.session` se mantiene como property read-only · backward-compat con
        # código externo (server.py auto_loop · trueno_sync) durante migration.
        self._session_auth = requests.Session()
        self._session_ops = requests.Session()
        _headers = {
            "User-Agent": "Mozilla/5.0 (Macintosh) AppleWebKit/537.36",
            "Origin": ORIGIN,
            "Referer": f"{ORIGIN}/",
            "Accept": "application/json, text/plain, */*",
        }
        self._session_auth.headers.update(_headers)
        self._session_ops.headers.update(_headers)
        self._refresh_thread = None
        self._refresh_stop = threading.Event()
        self._logged_in = False
        self._last_refresh = None             # timestamp last successful refresh/exchange
        self._token_expires_at = None         # epoch · cuándo expira access_token
        self._last_login_email = None
        self._lock = threading.RLock()        # RLock · permite recursion (verify→refresh→sync)
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
    def session(self):
        """Backward-compat · expone _session_ops como read-only.
        Code externo (server.py) que llamaba self.session.get debe migrar a método servicio.
        En migración mientras refactor server.py · esta property mantiene compat.
        WARNING · NO mutar cookies directo · usar refresh interno del service."""
        return self._session_ops

    @property
    def is_logged_in(self) -> bool:
        return self._logged_in and "access_token" in self._session_ops.cookies

    @property
    def cookies_summary(self) -> dict:
        return {
            c.name: f"{c.value[:25]}... ({len(c.value)} chars)"
            for c in self._session_ops.cookies
        }

    def _sync_cookies_to_ops(self) -> None:
        """Copy cookies de _session_auth a _session_ops atómicamente.
        Llamar solo DENTRO de self._lock · post-refresh OK."""
        # Clear ops cookies first · then copy from auth (atomic replacement effect)
        # NOTE · NO hacemos `_session_ops.cookies.clear()` antes para evitar
        #        ventana donde ops queda SIN cookies si refresh thread cae.
        #        Mejor copy individual · cookie por cookie · más resiliente.
        for c in self._session_auth.cookies:
            self._session_ops.cookies.set(
                c.name, c.value,
                domain=c.domain,
                path=c.path,
            )

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
            "cookies": [c.name for c in self._session_ops.cookies],
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

        # Reset cookies prev · ambas sessions (login fresh)
        self._session_auth.cookies.clear()
        self._session_ops.cookies.clear()

        try:
            r = self._session_auth.get(login_url, timeout=10)
            csrf_m = re.search(r'name="csrf" value="([^"]+)"', r.text)
            if not csrf_m:
                return {"ok": False, "error": "no_csrf_token", "message": "No se encontró CSRF en login page"}
            csrf = csrf_m.group(1)
        except Exception as e:
            return {"ok": False, "error": "network_error", "message": f"GET login page falló · {e}"}

        try:
            r2 = self._session_auth.post(
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
            r3 = self._session_auth.get(self._mfa_url, timeout=10)
            csrf_m = re.search(r'name="csrf" value="([^"]+)"', r3.text)
            if not csrf_m:
                return {"ok": False, "error": "no_csrf_mfa", "message": "No CSRF en MFA page"}
            csrf2 = csrf_m.group(1)
        except Exception as e:
            return {"ok": False, "error": "network_error", "message": str(e)}

        try:
            r4 = self._session_auth.post(
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
            r5 = self._session_auth.post(
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
        if "access_token" not in self._session_auth.cookies:
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

        # ROOT CAUSE FIX 2026-05-23 · prevent local cookie expiry
        # session_id Max-Age=3600s · server NO renueva en refresh · cookie expira en jar.
        # Setting expires=None prevents local expiry · server-side cookie still validated.
        for cookie in list(self._session_auth.cookies):
            if cookie.name in ("access_token", "session_id", "cognito", "post-auth"):
                cookie.expires = None

        # Sync auth cookies to ops session (atomic post-login fresh)
        with self._lock:
            self._sync_cookies_to_ops()
        self._cookie_access_token_value = self._session_auth.cookies.get("access_token")
        self._cookie_session_id_value = self._session_auth.cookies.get("session_id")
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

    # ============ Auto-login con pin service externo ============
    #
    # Permite a la app re-autenticarse sola cuando la sesión Relampago se pierde
    # (refresh loop agotó retries · cookies expiraron mientras estaba dormido · etc).
    # Necesita un pin-service HTTP que devuelva el TOTP actual (lo construimos
    # aparte sobre el share link 1Password con Playwright headless stealth).
    #
    # Configuración via server.py (env vars):
    #   RELAMPAGO_AUTO_LOGIN_ENABLED=1
    #   RELAMPAGO_AUTO_LOGIN_EMAIL=otc@vureloapp.com
    #   RELAMPAGO_AUTO_LOGIN_PASSWORD=...
    #   RELAMPAGO_PIN_SERVICE_URL=http://10.100.20.84:7321/pin
    #   RELAMPAGO_PIN_SERVICE_TOKEN=<bearer>

    def _fetch_pin_from_service(self, pin_url: str, pin_token: str) -> dict:
        """GET al pin-service · devuelve {ok, pin?, error?, ts?}."""
        try:
            r = requests.get(
                pin_url,
                headers={"Authorization": f"Bearer {pin_token}"},
                timeout=10,
            )
        except Exception as e:
            return {"ok": False, "error": f"network · {e}"}
        if r.status_code != 200:
            return {"ok": False, "error": f"HTTP {r.status_code} · {r.text[:200]}"}
        try:
            body = r.json()
        except Exception:
            return {"ok": False, "error": f"non-json · {r.text[:200]}"}
        pin = (body.get("pin") or "").strip()
        if not pin or not pin.isdigit() or len(pin) != 6:
            return {"ok": False, "error": f"pin inválido · {pin!r}"}
        return {"ok": True, "pin": pin, "ts": body.get("ts")}

    def auto_login_with_pin_service(
        self,
        email: str,
        password: str,
        pin_url: str,
        pin_token: str,
        max_attempts: int = 3,
    ) -> dict:
        """Login completo end-to-end · password + MFA via pin-service externo.

        Reintenta hasta `max_attempts` si el PIN expira entre fetch y submit
        (caso esquina · TOTP rota cada 30s · pin viejo da invalid_mfa).
        """
        last_detail = None
        for attempt in range(1, max_attempts + 1):
            r1 = self.login_password(email, password)
            if not r1.get("ok"):
                self._add_history({
                    "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "status": "AUTO_LOGIN_PASSWORD_FAIL",
                    "attempt": attempt,
                    "error": r1.get("error"),
                })
                return {"ok": False, "step": "password", "attempts": attempt, "detail": r1}

            r_pin = self._fetch_pin_from_service(pin_url, pin_token)
            if not r_pin.get("ok"):
                self._add_history({
                    "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "status": "AUTO_LOGIN_PIN_FETCH_FAIL",
                    "attempt": attempt,
                    "error": r_pin.get("error"),
                })
                return {"ok": False, "step": "pin_fetch", "attempts": attempt, "detail": r_pin}

            r2 = self.login_mfa(r_pin["pin"])
            if r2.get("ok"):
                self._add_history({
                    "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "status": "AUTO_LOGIN_OK",
                    "attempt": attempt,
                    "expires_in": r2.get("expires_in_seconds"),
                })
                return {
                    "ok": True,
                    "step": "complete",
                    "attempts": attempt,
                    "pin_ts": r_pin.get("ts"),
                    "expires_in_seconds": r2.get("expires_in_seconds"),
                }

            last_detail = r2
            # invalid_mfa probablemente es que el PIN expiró entre fetch y submit:
            # esperar 2s y reintentar con PIN fresh (idealmente cruza el window boundary)
            if r2.get("error") == "invalid_mfa" and attempt < max_attempts:
                self._add_history({
                    "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "status": "AUTO_LOGIN_MFA_RETRY",
                    "attempt": attempt,
                })
                time.sleep(2)
                continue
            self._add_history({
                "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
                "status": "AUTO_LOGIN_MFA_FAIL",
                "attempt": attempt,
                "error": r2.get("error"),
            })
            return {"ok": False, "step": "mfa", "attempts": attempt, "detail": r2}

        return {"ok": False, "step": "mfa_max_attempts", "attempts": max_attempts, "detail": last_detail}

    def start_auto_login_watchdog(
        self,
        email: str,
        password: str,
        pin_url: str,
        pin_token: str,
        check_interval: int = 30,
        cooldown_after_fail: int = 60,
    ) -> None:
        """Arranca thread que monitorea `is_logged_in` y auto-relogin cuando cae.

        Idempotente · si ya hay watchdog vivo no arranca otro.
        """
        existing = getattr(self, "_autologin_thread", None)
        if existing and existing.is_alive():
            return
        self._autologin_config = {
            "email": email,
            "password": password,
            "pin_url": pin_url,
            "pin_token": pin_token,
            "check_interval": check_interval,
            "cooldown_after_fail": cooldown_after_fail,
        }
        self._autologin_stop = threading.Event()
        self._autologin_last_attempt_at = None
        self._autologin_last_result = None

        def loop():
            print(f"▶ Auto-login watchdog ON · interval={check_interval}s · email={email}")
            while not self._autologin_stop.is_set():
                try:
                    if not self.is_logged_in:
                        print(f"⚠ Watchdog · sesión Relampago caída · auto-login...")
                        self._autologin_last_attempt_at = time.time()
                        r = self.auto_login_with_pin_service(email, password, pin_url, pin_token)
                        self._autologin_last_result = r
                        if r.get("ok"):
                            print(
                                f"✓ Auto-login OK · attempts={r.get('attempts')} "
                                f"· expires_in={r.get('expires_in_seconds')}s"
                            )
                        else:
                            print(
                                f"✗ Auto-login FAIL · step={r.get('step')} "
                                f"attempts={r.get('attempts')} · cooldown {cooldown_after_fail}s"
                            )
                            if self._autologin_stop.wait(cooldown_after_fail):
                                break
                            continue
                except Exception as e:
                    print(f"⚠ Watchdog inner exception · {e}")
                if self._autologin_stop.wait(check_interval):
                    break
            print("· Auto-login watchdog stopped")

        self._autologin_thread = threading.Thread(
            target=loop, daemon=True, name="relampago-autologin-watchdog"
        )
        self._autologin_thread.start()

    def stop_auto_login_watchdog(self) -> None:
        """Detiene el watchdog · safe si nunca arrancó."""
        if hasattr(self, "_autologin_stop"):
            self._autologin_stop.set()

    def autologin_status(self) -> dict:
        """Snapshot del watchdog · seguro para exponer en /api/status."""
        cfg = getattr(self, "_autologin_config", None)
        thr = getattr(self, "_autologin_thread", None)
        last_r = getattr(self, "_autologin_last_result", None)
        return {
            "enabled": cfg is not None,
            "running": bool(thr and thr.is_alive()),
            "email": cfg.get("email") if cfg else None,
            "pin_service_url": cfg.get("pin_url") if cfg else None,
            "check_interval_s": cfg.get("check_interval") if cfg else None,
            "last_attempt_at": getattr(self, "_autologin_last_attempt_at", None),
            "last_result": (
                {"ok": last_r.get("ok"), "step": last_r.get("step"), "attempts": last_r.get("attempts")}
                if last_r else None
            ),
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

        ARCHITECTURE FIX 2026-05-23 · try/except outer · sobrevive cualquier
        exception interna (time.sleep · print · etc) que antes mataba el thread silente.
        """
        try:
            while not self._refresh_stop.is_set():
                try:
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
                except Exception as inner_e:
                    # Inner exception · log + continúa al próximo cycle (NO mata thread)
                    print(f"⚠ Refresh loop inner exception · {inner_e} · sleeping 30s antes de retry")
                    self._add_history({
                        "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
                        "status": "INNER_EXCEPTION",
                        "error": str(inner_e)[:200],
                    })
                    if self._refresh_stop.wait(30):
                        break
        except Exception as outer_e:
            # Outer exception · catastrófico · log + permite restart manual
            print(f"⚠⚠⚠ Refresh loop OUTER exception · thread terminating · {outer_e}")
            self._add_history({
                "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
                "status": "OUTER_EXCEPTION",
                "error": str(outer_e)[:200],
            })

    def _do_refresh(self) -> bool:
        """
        Ejecuta UN intento de refresh.
        True · refresh OK · cookies rotated · _token_expires_at actualizado
        False · server dijo "not ready" · 4xx · o network error
        """
        with self._lock:
            try:
                r = self._session_auth.post(
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

                # ============ ROOT CAUSE FIX 2026-05-23 · session_id local expiry ============
                # Server Relampago Pay · session_id cookie Max-Age=3600s · server NO renueva
                # session_id en cada refresh (solo access_token rota). A los 60 min post-login
                # fresh · session_id EXPIRA en local cookie jar (requests cleans expired cookies).
                # Próximo refresh va SIN session_id · server 500 → 500 → 403 · SESIÓN PERDIDA.
                #
                # Pattern observado · TIMING ANALYSIS log:
                #   18:54:51 LOGIN · session_id rotated=TRUE
                #   19:04:43 refresh · rotated=FALSE (server keeps same)
                #   ... (todos rotated=FALSE)
                #   19:53:58 fail HTTP 500 (53s pre-3600s expire teórico)
                #   19:54:08 REVOKED 403 · session perdida
                #
                # FIX · forzar `expires=None` en cookies post-refresh OK.
                # `requests.Session` cookie jar limpia cookies expired locally.
                # Setting expires=None hace que cookie NUNCA expire en local jar.
                # Server-side · sigue válido (session_id is opaque para server).
                for cookie in list(self._session_auth.cookies):
                    if cookie.name in ("access_token", "session_id", "cognito", "post-auth"):
                        cookie.expires = None  # never expire locally · keep alive

                # Sync cookies from auth → ops atomic (POST refresh OK)
                self._sync_cookies_to_ops()
                new_access = self._session_auth.cookies.get("access_token")
                new_session = self._session_auth.cookies.get("session_id")
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
                for c in self._session_auth.cookies
            }
            storage.save_session(
                cookies=cookies_dict,
                email=self._last_login_email or "",
                last_refresh=self._last_refresh or 0,
                token_expires_at=self._token_expires_at or 0,
                refresh_count=self._refresh_count,
                session_started_at=self._session_started_at,
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
            # Load cookies a _session_auth · luego sync ops
            for name, info in data["cookies"].items():
                self._session_auth.cookies.set(
                    name,
                    info["value"],
                    domain=info.get("domain"),
                    path=info.get("path", "/"),
                )

            # ROOT CAUSE FIX 2026-05-23 · prevent local cookie expiry post-restore
            # SQLite restore puede traer cookies con expires viejos · forzar expires=None
            for cookie in list(self._session_auth.cookies):
                if cookie.name in ("access_token", "session_id", "cognito", "post-auth"):
                    cookie.expires = None

            # Sync cookies a _session_ops (atómico bajo lock)
            with self._lock:
                self._sync_cookies_to_ops()
            self._last_login_email = data.get("email")
            self._last_refresh = data.get("last_refresh")
            self._token_expires_at = data.get("token_expires_at")
            self._refresh_count = data.get("refresh_count", 0)
            # Restaurar session_started_at si está persistido
            sa = data.get("session_started_at")
            if sa:
                self._session_started_at = sa
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
        if "access_token" not in self._session_ops.cookies:
            return False
        try:
            with self._lock:
                r = self._session_ops.get(f"{API_BASE}/account/balance", timeout=8)
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
                self._session_auth.cookies.clear()
                self._session_ops.cookies.clear()
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
            self._session_auth.post(f"{API_BASE}/auth/logout", timeout=5)
        except Exception:
            pass
        self._refresh_stop.set()
        with self._lock:
            self._session_auth.cookies.clear()
            self._session_ops.cookies.clear()
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
            with self._lock:
                r = self._session_ops.get(f"{API_BASE}/account/balance", timeout=10)
            if r.status_code == 200:
                return {"ok": True, "data": r.json().get("data", {})}
            return {"ok": False, "error": f"http_{r.status_code}", "body": r.text[:300]}
        except Exception as e:
            return {"ok": False, "error": "network_error", "message": str(e)}

    def get_trueno_transactions(self) -> dict:
        """Trae transacciones del accountType=Trueno · usado por server.py _trueno_sync.
        2026-05-23 · NUEVO método para encapsular · server.py NO debe acceder _session_ops direct."""
        if not self.is_logged_in:
            return {"ok": False, "error": "not_logged_in"}
        try:
            with self._lock:
                r = self._session_ops.get(
                    f"{API_BASE}/account/transactions",
                    params={"accountType": "Trueno"},
                    timeout=15,
                )
            if r.status_code != 200:
                return {"ok": False, "status": r.status_code, "body": r.text[:300]}
            return {"ok": True, "data": r.json().get("data", {})}
        except Exception as e:
            return {"ok": False, "error": "network_error", "message": str(e)}

    def get_ach_transactions(self) -> dict:
        """Trae transacciones del accountType=Turbo-ACH · estado REAL de las
        dispersiones ACH (created → approved/rejected). 2026-06-17.

        Shape idéntico a get_trueno_transactions (data.transfers[] con
        transactionId/state/declinationReason) · por eso alimenta el MISMO
        store (upsert_trueno_transaction) y el finalize las cierra igual que BReB.
        El estado 'created' = solo enviado · NO notificar approved/rejected hasta
        que el state sea final."""
        if not self.is_logged_in:
            return {"ok": False, "error": "not_logged_in"}
        try:
            with self._lock:
                r = self._session_ops.get(
                    f"{API_BASE}/account/transactions",
                    params={"accountType": "Turbo-ACH"},
                    timeout=15,
                )
            if r.status_code != 200:
                return {"ok": False, "status": r.status_code, "body": r.text[:300]}
            return {"ok": True, "data": r.json().get("data", {})}
        except Exception as e:
            return {"ok": False, "error": "network_error", "message": str(e)}

    def get_bank_codes(self) -> dict:
        try:
            with self._lock:
                r = self._session_ops.get(f"{API_BASE}/account/bank-codes", timeout=10)
            return {"ok": r.status_code == 200, "data": r.json().get("data") if r.status_code == 200 else None}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def get_transactions(self) -> dict:
        try:
            with self._lock:
                r = self._session_ops.get(f"{API_BASE}/account/transactions", timeout=10)
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
            with self._lock:
                r = self._session_ops.post(
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
            with self._lock:
                r = self._session_ops.post(
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

    # ============ ACH dispersion (2026-06-16) ============
    #
    # ACH usa el MISMO endpoint /transactions/execute que BReB · solo cambia
    # routing="ach" y el bloque payee.bank_account lleva cuenta bancaria completa
    # (type+bank_code+number) en vez de solo la llave. Shape verificado contra una
    # ejecución real del portal (POST /v0/transactions/execute · 201 Created).
    #
    # A diferencia de BReB, ACH NO pre-valida vía /resolve-payee (ese endpoint
    # valida llaves BReB) · la validez de la cuenta la responde execute directamente.
    # build_ach_transfer es puro (sin red) · el caller lo pasa a execute_dispersion.

    # Mapeo del account_type Vurelo (CHECKING|SAVINGS) → shape Relampago.
    _ACH_ACCOUNT_TYPE_MAP = {
        "SAVINGS": "savings_account",
        "CHECKING": "checking_account",
        "savings_account": "savings_account",
        "checking_account": "checking_account",
    }

    def build_ach_transfer(
        self,
        *,
        account_number: str,
        bank_code: str,
        account_type: str,
        document_type: str,
        document_number: str,
        name: str,
        amount_cents: int,
        bank_name: str = "",
        description: str = "",
        reference: str = "",
        emails_to_notify: list | None = None,
    ) -> dict:
        """Construye un transfer ACH para execute_dispersion. Puro · sin red.

        amount_cents · virtualAmount en CENTAVOS COP (= pesos × 100).
        account_type · acepta 'SAVINGS'/'CHECKING' (Vurelo) o '*_account' (Relampago).
        """
        rel_type = self._ACH_ACCOUNT_TYPE_MAP.get(
            (account_type or "").strip(), "savings_account"
        )
        return {
            "virtualAmount": int(amount_cents),
            "payee": {
                "bank_account": {
                    "type": rel_type,
                    "bank_code": str(bank_code or ""),
                    "bank_name": str(bank_name or ""),
                    "number": str(account_number or ""),
                },
                "document_type": str(document_type or ""),
                "document_number": str(document_number or ""),
                "name": str(name or ""),
            },
            "routing": "ach",
            "description": description or "",
            "emails_to_notify": emails_to_notify or [],
            "reference": reference or "",
        }
