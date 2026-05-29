"""
Vurelo Relampago Operator · service local.

Uso:
   python3 server.py                  · default (modo persistido en DB · o manual si vacío)
   python3 server.py --auto           · forzar AUTO mode al startup
   python3 server.py --manual         · forzar MANUAL al startup
   python3 server.py --port 9000      · custom port
   python3 server.py --no-open        · no auto-open browser
   python3 server.py --logout         · borra sesión persistida y sale
   python3 server.py --status         · imprime status y sale

UI: http://localhost:8787
"""
import argparse
import json
import os
import signal
import sys
import threading
import time
import webbrowser
from flask import Flask, render_template, request, jsonify

from relampago import RelampagoSession
from kashport import KashportClient
import storage
import notifier
import google_oauth
import auth as gauth
import vurelo_webhook  # 2026-05-29 · cierre saga BREB_CASHOUT api.vurelo.co
import vurelo_queue    # 2026-05-29 · poll backend HAv1 BREB cashout queue (replaces kashport poll)

app = Flask(__name__, static_folder="static", template_folder="templates")

# Init SQLite
storage.init_db()

# ============ Google Auth gate · before_request ============

@app.before_request
def _auth_gate():
    return gauth.require_auth()

# Singleton de sesión Relampago + Kashport client
relampago = RelampagoSession()
kashport = KashportClient()

# State global · modo auto · processed/skipped
AUTO_MODE = {"enabled": False}
PROCESSED_IDS = set()        # items que ya iniciamos a procesar (submit-once persistido in-memory)
COMPLETED_IDS = set()        # mark-paid OK
FAILED_IDS = {}              # id → attempts
EVENT_LOG = []               # últimos eventos · UI debug
LOG_MAX = 200

# 2026-05-29 · queue source · ÚNICO · Vurelo backend HAv1 (legacy Kashport eliminado)
QUEUE_SOURCE = "vurelo"  # forced · ignora env por seguridad · NO más Kashport
VURELO_CACHE = {
    "ok": None,
    "data": None,
    "fetched_at": None,
    "fetched_epoch": None,
    "consecutive_errors": 0,
    "error": None,
    "last_item_count": 0,
}


def log_event(kind: str, payload: dict):
    EVENT_LOG.append({
        "kind": kind,
        "ts": time.strftime("%H:%M:%S"),
        "payload": payload,
    })
    if len(EVENT_LOG) > LOG_MAX:
        del EVENT_LOG[: len(EVENT_LOG) - LOG_MAX]


# ============ Routes · UI ============

@app.route("/")
def index():
    return render_template("index.html")


# ============ Google OAuth ============

OAUTH_STATE_COOKIE = "vurelo-oauth-state"
OAUTH_NEXT_COOKIE = "vurelo-oauth-next"


def _public_base() -> str:
    """URL base pública · usa PUBLIC_BASE_URL env o host del request."""
    env = os.environ.get("PUBLIC_BASE_URL", "").strip()
    if env:
        return env.rstrip("/")
    xfh = request.headers.get("X-Forwarded-Host")
    xfp = request.headers.get("X-Forwarded-Proto", "https")
    if xfh:
        return f"{xfp}://{xfh}"
    return request.host_url.rstrip("/")


@app.route("/login")
def login_page():
    next_url = request.args.get("next", "/")
    err = request.args.get("err", "")
    return render_template("login.html",
                           next_url=next_url, err=err,
                           google_configured=google_oauth.is_configured())


@app.route("/api/auth/google/start")
def auth_google_start():
    if not google_oauth.is_configured():
        return jsonify({"error": "google_not_configured"}), 503
    redirect_uri = f"{_public_base()}/api/auth/google/callback"
    next_url = request.args.get("next", "/")
    import secrets
    state = secrets.token_hex(16)
    auth_url = google_oauth.build_auth_url(redirect_uri, state)
    from flask import make_response, redirect as flask_redirect
    resp = make_response(flask_redirect(auth_url))
    secure = _public_base().startswith("https://")
    resp.set_cookie(OAUTH_STATE_COOKIE, state, httponly=True, secure=secure,
                    samesite="Lax", max_age=600, path="/")
    resp.set_cookie(OAUTH_NEXT_COOKIE, next_url, httponly=True, secure=secure,
                    samesite="Lax", max_age=600, path="/")
    return resp


@app.route("/api/auth/google/callback")
def auth_google_callback():
    from flask import make_response, redirect as flask_redirect
    code = request.args.get("code")
    state = request.args.get("state")
    err = request.args.get("error")

    def err_redirect(msg):
        resp = make_response(flask_redirect(f"/login?err={msg}"))
        resp.delete_cookie(OAUTH_STATE_COOKIE)
        resp.delete_cookie(OAUTH_NEXT_COOKIE)
        return resp

    if err:
        return err_redirect(f"Google · {err}")
    if not code or not state:
        return err_redirect("callback inválido · falta code o state")

    expected_state = request.cookies.get(OAUTH_STATE_COOKIE)
    if not expected_state or expected_state != state:
        return err_redirect("state CSRF inválido · reintenta")

    next_url = request.cookies.get(OAUTH_NEXT_COOKIE) or "/"
    if not next_url.startswith("/") or next_url.startswith("//"):
        next_url = "/"

    redirect_uri = f"{_public_base()}/api/auth/google/callback"
    try:
        tokens = google_oauth.exchange_code(code, redirect_uri)
        profile = google_oauth.verify_id_token(tokens["id_token"])
    except Exception as e:
        return err_redirect(str(e))

    session_cookie = gauth.sign_session({
        "email": profile["email"],
        "name": profile.get("name") or profile["email"].split("@")[0],
        "picture": profile.get("picture"),
        "sub": profile.get("sub"),
    })

    resp = make_response(flask_redirect(next_url))
    secure = _public_base().startswith("https://")
    resp.set_cookie(gauth.AUTH_COOKIE_NAME, session_cookie,
                    httponly=True, secure=secure, samesite="Lax",
                    max_age=gauth.AUTH_TTL_SECONDS, path="/")
    resp.delete_cookie(OAUTH_STATE_COOKIE)
    resp.delete_cookie(OAUTH_NEXT_COOKIE)
    log_event("google_login", {"email": profile["email"]})
    return resp


@app.route("/api/auth/google/logout", methods=["POST", "GET"])
def auth_google_logout():
    from flask import make_response, redirect as flask_redirect
    resp = make_response(flask_redirect("/login"))
    resp.delete_cookie(gauth.AUTH_COOKIE_NAME)
    return resp


@app.route("/api/me")
def api_me():
    user = gauth.get_current_user()
    if not user:
        return jsonify({"authenticated": False}), 401
    return jsonify({"authenticated": True, "user": user})


# ============ Routes · API ============

@app.route("/api/status")
def api_status():
    return jsonify({
        "relampago": relampago.status,
        "kashport_configured": kashport.configured,
        "auto_mode": AUTO_MODE["enabled"],
        "processed_count": len(PROCESSED_IDS),
        "completed_count": len(COMPLETED_IDS),
        "failed_count": len(FAILED_IDS),
        "service": {
            "auto_loop_running": _auto_thread is not None and _auto_thread.is_alive(),
            "trueno_sync_running": _trueno_thread is not None and _trueno_thread.is_alive(),
        },
    })


@app.route("/api/login/password", methods=["POST"])
def api_login_password():
    body = request.get_json(force=True, silent=True) or {}
    email = (body.get("email") or "").strip()
    password = body.get("password") or ""
    if not email or not password:
        return jsonify({"ok": False, "error": "missing_fields"}), 400
    result = relampago.login_password(email, password)
    log_event("login_password", {"email": email, "ok": result.get("ok"), "next": result.get("next_step")})
    return jsonify(result)


@app.route("/api/login/mfa", methods=["POST"])
def api_login_mfa():
    body = request.get_json(force=True, silent=True) or {}
    pin = (body.get("pin") or "").strip()
    if not pin:
        return jsonify({"ok": False, "error": "missing_pin"}), 400
    result = relampago.login_mfa(pin)
    log_event("login_mfa", {"ok": result.get("ok"), "message": result.get("message")})
    if result.get("ok"):
        # Audit fix 2026-05-23 · si auto_mode está enabled · arrancar loops automático
        # post-login. Pre-fix · solo _start_trueno_sync · auto_loop NO arrancaba post-MFA
        # y user tenía que toggle manual auto OFF→ON para activar. Bug observado tras
        # container restart + re-login.
        _start_trueno_sync()
        # Vurelo poller arranca siempre (independiente auto_mode)
        if QUEUE_SOURCE == "vurelo" and vurelo_queue.is_configured():
            _start_vurelo_poller()
        if AUTO_MODE["enabled"]:
            _start_auto_loop()
            if QUEUE_SOURCE == "kashport":
                _start_kashport_poller()
            log_event("auto_loops_started_post_login", {"trigger": "login_mfa", "queue": QUEUE_SOURCE})
            print(f"▶ AUTO loop arrancado post-MFA (auto_mode=ON · queue={QUEUE_SOURCE})")
    return jsonify(result)


@app.route("/api/logout", methods=["POST"])
def api_logout():
    relampago.logout()
    log_event("logout", {})
    return jsonify({"ok": True})


@app.route("/api/refresh-history")
def api_refresh_history():
    """
    Diagnostic 2026-05-23 · ver patrón refresh para entender cuándo/por qué se cierra sesión.
    Retorna last 50 refresh events · cada uno con timestamp · status · cookies rotated.
    Útil para detectar:
       · Cognito refresh_token expiry (~30 días post-login fresh)
       · Network errors patterns (NETWORK_ERROR consecutivos)
       · Server-side revoke (REVOKED status code 401/403)
       · Cookie rotation issues (access_token_rotated=false en OK · server NO rotó)
    """
    return jsonify({
        "history": relampago.refresh_history,
        "summary": {
            "total_events": len(relampago.refresh_history),
            "session_started_iso": relampago.status.get("session_started_iso"),
            "session_age_hours": relampago.status.get("session_age_hours"),
            "session_age_days": relampago.status.get("session_age_days"),
            "cognito_refresh_token_days_left": relampago.status.get("cognito_refresh_token_days_left"),
            "refresh_count": relampago._refresh_count,
            "refresh_errors": relampago._refresh_errors,
            "consecutive_errors": relampago._consecutive_errors,
        },
    })


@app.route("/api/refresh", methods=["POST"])
def api_refresh():
    result = relampago.force_refresh()
    log_event("refresh_manual", result)
    return jsonify(result)


@app.route("/api/balance")
def api_balance():
    result = relampago.get_balance()
    # Check thresholds y disparar alertas si aplica (only-one logic)
    if result.get("ok"):
        try:
            _check_balance_thresholds(result["data"].get("accounts", []))
        except Exception as e:
            log_event("threshold_check_error", {"error": str(e)})
    return jsonify(result)


def _check_balance_thresholds(accounts: list):
    """
    Para cada account · checa si está bajo el threshold · envía email UNA SOLA VEZ
    por "evento de saldo bajo" (reset cuando vuelve arriba).
    """
    for acc in accounts:
        acc_type = acc.get("accountType")
        balance = acc.get("actualBalance", 0)
        acc_id = acc.get("accountId", "")

        thr = storage.get_threshold(acc_type)
        if not thr or not thr.get("enabled"):
            continue

        threshold = thr["threshold_cop"]
        last_alert = thr.get("last_alert_sent_at")

        if balance < threshold:
            # Bajo el umbral · ¿alertar?
            if last_alert is None:
                # Nunca alertado en este "evento" · enviar AHORA
                result = notifier.send_low_balance_alert(
                    account_type=acc_type, account_id=acc_id,
                    current_balance=balance, threshold=threshold,
                )
                if result.get("ok"):
                    storage.mark_alert_sent(acc_type, balance)
                    log_event("low_balance_alert_sent", {
                        "account_type": acc_type,
                        "balance": balance,
                        "threshold": threshold,
                        "recipients_count": result.get("recipients_count"),
                    })
                else:
                    log_event("low_balance_alert_failed", {
                        "account_type": acc_type, "error": result.get("error"),
                    })
            # else · ya se alertó · skip (only-one logic)
        else:
            # Saldo arriba del umbral · si había alerta · reset (próxima vez vuelve a enviar)
            if last_alert is not None:
                storage.reset_alert_state(acc_type)
                log_event("balance_recovered", {
                    "account_type": acc_type, "balance": balance, "threshold": threshold,
                })


@app.route("/api/thresholds")
def api_thresholds():
    return jsonify({"items": storage.list_thresholds()})


@app.route("/api/thresholds/<account_type>", methods=["POST"])
def api_set_threshold(account_type):
    body = request.get_json(force=True, silent=True) or {}
    threshold = body.get("threshold_cop")
    enabled = body.get("enabled", True)
    if threshold is None:
        return jsonify({"ok": False, "error": "threshold_cop required"}), 400
    storage.set_threshold(account_type, float(threshold), bool(enabled))
    log_event("threshold_updated", {"account_type": account_type, "threshold": threshold, "enabled": enabled})
    return jsonify({"ok": True})


@app.route("/api/recipients", methods=["GET", "POST"])
def api_recipients():
    if request.method == "GET":
        return jsonify({"recipients": notifier.get_recipients()})
    body = request.get_json(force=True, silent=True) or {}
    emails = body.get("emails") or []
    notifier.set_recipients(emails)
    log_event("recipients_updated", {"count": len(emails)})
    return jsonify({"ok": True, "recipients": notifier.get_recipients()})


@app.route("/api/dispersion-rules", methods=["GET", "POST"])
def api_dispersion_rules():
    if request.method == "GET":
        return jsonify({
            "min_gap_seconds": int(storage.get_setting("dispersion_min_gap_seconds", "15") or "15"),
            "same_payee_window_minutes": int(storage.get_setting("dispersion_same_payee_window_minutes", "10") or "10"),
        })
    body = request.get_json(force=True, silent=True) or {}
    if "min_gap_seconds" in body:
        v = max(0, int(body["min_gap_seconds"]))
        storage.set_setting("dispersion_min_gap_seconds", str(v))
    if "same_payee_window_minutes" in body:
        v = max(0, int(body["same_payee_window_minutes"]))
        storage.set_setting("dispersion_same_payee_window_minutes", str(v))
    log_event("dispersion_rules_updated", body)
    return jsonify({
        "ok": True,
        "min_gap_seconds": int(storage.get_setting("dispersion_min_gap_seconds", "15")),
        "same_payee_window_minutes": int(storage.get_setting("dispersion_same_payee_window_minutes", "10")),
    })


@app.route("/api/test-email", methods=["POST"])
def api_test_email():
    result = notifier.send_test_email()
    log_event("test_email", {"ok": result.get("ok"), "error": result.get("error")})
    return jsonify(result)


@app.route("/api/bank-codes")
def api_bank_codes():
    return jsonify(relampago.get_bank_codes())


@app.route("/api/transactions")
def api_transactions():
    return jsonify(relampago.get_transactions())


@app.route("/api/kashport/token", methods=["POST"])
def api_kashport_token():
    body = request.get_json(force=True, silent=True) or {}
    token = body.get("token") or ""
    kashport.set_token(token)
    # Persistir en SQLite
    if token:
        storage.set_setting("kashport_token", token)
    else:
        storage.delete_setting("kashport_token")
    log_event("kashport_token_updated", {"configured": kashport.configured})
    return jsonify({"ok": True, "configured": kashport.configured, "persisted": True})


def _annotate_queue_with_rules(data: dict) -> dict:
    """
    Para cada item · agregar rule_check · {ok, reason?, detail?, wait_seconds?}.
    UI usa esto para deshabilitar botón "▶ Procesar" si bloqueo activo.
    """
    if not data or not data.get("items"):
        return data
    for it in data["items"]:
        d = it.get("destination") or {}
        key = d.get("key_value") or d.get("account_number")
        amount = it.get("amount_cop") or it.get("amount") or 0
        if key and amount:
            try:
                check = storage.check_dispersion_rules(key, int(amount))
                it["rule_check"] = check
            except Exception as e:
                it["rule_check"] = {"ok": True, "error": str(e)}
    return data


def _vurelo_item_to_ui_shape(v: dict) -> dict:
    """
    Adapter · Vurelo backend item shape → UI shape esperada (compat con kashport).
    Mantiene los campos legacy para que la UI siga funcionando + agrega los
    nuevos campos del flow Vurelo.
    """
    dest = v.get("destination") or {}
    claim = v.get("claim") or {}
    return {
        # UI legacy fields (compat)
        "id": v.get("tx_id", ""),
        "amount_cop": v.get("amount_cop_pesos", 0),
        "amount": v.get("amount_cop_pesos", 0),
        "rail": "breb",
        "oldvprovider_id": v.get("external_id"),  # = "fast_pay:trx_xxx"
        "destination": {
            "key_value": dest.get("breb_key"),
            "key_type": dest.get("breb_key_type"),
            "fullname": v.get("description"),
        },
        # New Vurelo fields
        "tx_id": v.get("tx_id"),
        "external_id": v.get("external_id"),
        "source_currency": v.get("source_currency"),
        "source_value": v.get("source_value"),
        "user_uuid": v.get("user_uuid"),
        "claim": claim,
        "cobre_payment_id": v.get("cobre_payment_id"),
        "cobre_status": v.get("cobre_status"),
        "source": "vurelo",
        "_raw": v,
    }


@app.route("/api/queue")
def api_queue():
    """
    Queue source · controlado por env QUEUE_SOURCE (default 'vurelo').

    QUEUE_SOURCE = 'vurelo' · usa VURELO_CACHE del poller background o fetch
                              directo si AUTO OFF · single source of truth.
    QUEUE_SOURCE = 'kashport' · legacy · usa KASHPORT_CACHE / kashport.pending()

    Cada item es anotado con rule_check (anti-duplicado + gap).
    """
    if QUEUE_SOURCE == "vurelo":
        # Use VURELO_CACHE si hay data fresca · sino fetch directo
        if VURELO_CACHE["data"] is not None and AUTO_MODE.get("enabled", False):
            items_raw = (VURELO_CACHE["data"] or {}).get("items", [])
            ui_items = [_vurelo_item_to_ui_shape(v) for v in items_raw]
            data = {"items": ui_items, "count": len(ui_items)}
            annotated = _annotate_queue_with_rules(data)
            return jsonify({
                "ok": True,
                "data": annotated,
                "fetched_at": VURELO_CACHE["fetched_at"],
                "from_cache": True,
                "source": "vurelo",
                "error": VURELO_CACHE.get("error"),
            })
        # Direct fetch
        r = vurelo_queue.pending(limit=100, include_claimed=False)
        if not r.get("ok"):
            return jsonify({
                "ok": False,
                "source": "vurelo",
                "error": r.get("error") or r.get("body"),
                "data": {"items": [], "count": 0},
            })
        ui_items = [_vurelo_item_to_ui_shape(v) for v in r.get("items", [])]
        data = {"items": ui_items, "count": len(ui_items)}
        annotated = _annotate_queue_with_rules(data)
        return jsonify({
            "ok": True,
            "data": annotated,
            "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()),
            "from_cache": False,
            "source": "vurelo",
        })

    # Unreachable · QUEUE_SOURCE forced "vurelo" arriba
    return jsonify({"ok": False, "error": "unreachable", "source": QUEUE_SOURCE})


@app.route("/api/process/<item_id>", methods=["POST"])
def api_process(item_id):
    """
    2026-05-29 · UI legacy ruta · si item_id es trx_xxx (Vurelo backend) ·
    forwardea a api_process_vurelo. Si NO empieza con trx_ · legacy 410.
    Esto mantiene compat con UI viejo sin tocar el template HTML.
    """
    if item_id and item_id.startswith("trx_"):
        log_event("api_process_legacy_routed_to_vurelo", {"tx_id": item_id})
        return api_process_vurelo(item_id)
    return jsonify({
        "ok": False,
        "error": "legacy_kashport_flow_disabled",
        "message": "Solo trx_xxx aceptado · use /api/process-vurelo/<tx_id>",
    }), 410


def _legacy_api_process_disabled(item_id):
    """Code legacy preservado por referencia · no se invoca."""
    # Hard guard · submit-once
    if item_id in PROCESSED_IDS or item_id in COMPLETED_IDS:
        return jsonify({
            "ok": False,
            "error": "already_processed",
            "message": "Item ya fue procesado en esta sesión · skip (anti-doble)",
        })

    PROCESSED_IDS.add(item_id)
    log_event("process_start", {"item_id": item_id})

    if not relampago.is_logged_in:
        PROCESSED_IDS.discard(item_id)
        return jsonify({"ok": False, "error": "not_logged_in"})

    # Obtener detalle del item desde la queue (necesario para llave + amount)
    queue_resp = kashport.pending()
    if not queue_resp.get("ok"):
        PROCESSED_IDS.discard(item_id)
        return jsonify({"ok": False, "error": "queue_fetch_failed", "detail": queue_resp})

    items = queue_resp["data"].get("items", [])
    item = next((it for it in items if it.get("id") == item_id), None)
    if not item:
        PROCESSED_IDS.discard(item_id)
        return jsonify({"ok": False, "error": "item_not_in_queue"})

    key = (item.get("destination") or {}).get("key_value") or (item.get("destination") or {}).get("account_number")
    # IMPORTANTE · virtualAmount está en CENTAVOS COP · descubierto 2026-05-22
    # Kashport item trae amount_cop en pesos · multiply x100 para Relampago
    amount_cop_pesos = item.get("amount_cop") or item.get("amount") or 0
    virtual_amount_cents = int(round(float(amount_cop_pesos) * 100))
    routing = item.get("rail") or "breb"

    # Step 0 · check reglas de dispersión (anti-doble + min gap)
    rules_check = storage.check_dispersion_rules(key, int(amount_cop_pesos))
    if not rules_check.get("ok"):
        PROCESSED_IDS.discard(item_id)
        log_event("rule_blocked", {"item_id": item_id, "reason": rules_check.get("reason"), "detail": rules_check.get("detail")})
        return jsonify({
            "ok": False,
            "rule_blocked": True,
            "reason": rules_check.get("reason"),
            "message": rules_check.get("detail"),
            "wait_seconds": rules_check.get("wait_seconds"),
            "minutes_ago": rules_check.get("minutes_ago"),
            "last_tx_id": rules_check.get("last_tx_id"),
        })

    # Step 1 · resolve-payee (validar llave)
    resolve = relampago.resolve_payee(key, virtual_amount_cents, routing=routing)
    if resolve.get("status") == 404:
        # Llave inválida · auto-reject + persistir en attention
        d = item.get("destination") or {}
        payee_name = d.get("fullname") or d.get("name") or "(sin nombre)"
        doc = d.get("doc_number") or d.get("doc") or "?"

        log_event("payee_invalid", {"item_id": item_id, "key": key, "payee": payee_name})
        rej = kashport.mark_rejected(
            item_id,
            reason="payee_key_invalid",
            detail="Llave BREB no encontrada · validado vía Relampago API",
        )
        log_event("auto_rejected", {"item_id": item_id, "kashport_resp": rej})

        # Persistir en attention_items para audit + review operador
        try:
            storage.add_attention(
                kind="auto_rejected_payee_invalid",
                severity="warn",
                relampago_tx_id=None,
                external_id=None,
                kashport_provider_id=item.get("oldvprovider_id"),
                payee_name=payee_name,
                amount_cop=int(amount_cop_pesos),
                description=f"Llave BREB inválida · {key} · {payee_name} (CC {doc}) · monto ${int(amount_cop_pesos):,.0f}",
                detail_json={
                    "kashport_id": item_id,
                    "kashport_provider_id": item.get("oldvprovider_id"),
                    "key_tried": key,
                    "amount_cop": int(amount_cop_pesos),
                    "rail": routing,
                    "payee_doc": doc,
                    "resolve_response": resolve.get("data"),
                    "kashport_reject_result": rej,
                },
            )
        except Exception as e:
            log_event("attention_persist_error", {"error": str(e)})

        return jsonify({
            "ok": False,
            "auto_rejected": True,
            "key": key,
            "message": "Llave inválida · auto-rechazada · refund al user · agregada a Atención",
            "resolve": resolve,
            "kashport_reject": rej,
        })
    if not resolve.get("ok"):
        log_event("resolve_error", {"item_id": item_id, "resolve": resolve})
        FAILED_IDS[item_id] = FAILED_IDS.get(item_id, 0) + 1
        PROCESSED_IDS.discard(item_id)
        return jsonify({"ok": False, "error": "resolve_failed", "detail": resolve})

    # Step 2 · execute dispersión · usar el transfer validado del resolve
    # (incluye payee enriquecido + signature)
    resolve_data = resolve.get("data", {}).get("data", {})
    validated_transfers = resolve_data.get("transfers", [])
    if not validated_transfers:
        return jsonify({"ok": False, "error": "no_validated_transfer"})

    # Personalizar el description/reference con el oldvprovider_id
    validated = validated_transfers[0]
    validated["description"] = item.get("oldvprovider_id", "Vurelo dispersion")
    validated["reference"] = item.get("oldvprovider_id", "")

    execute = relampago.execute_dispersion([validated])
    log_event("execute_attempt", {"item_id": item_id, "resp_status": execute.get("status")})

    if not execute.get("ok"):
        # 2026-05-23 audit GAP fix · NO mark-paid · submit falló · attention_items critical.
        # Item queda en processed_ids in-memory (anti-retry esta sesión) · operador manual review.
        log_event("execute_failed", {"item_id": item_id, "detail": execute})
        try:
            storage.add_attention(
                kind="execute_failed",
                severity="critical",
                relampago_tx_id=None,
                external_id=None,
                kashport_provider_id=item.get("oldvprovider_id"),
                payee_name=(item.get("destination") or {}).get("fullname") or "(sin nombre)",
                amount_cop=int(amount_cop_pesos),
                description=(
                    f"Relampago execute FALLÓ · ${int(amount_cop_pesos):,.0f} → {key} · "
                    f"status={execute.get('status')} · revisar Trueno manualmente"
                ),
                detail_json={
                    "kashport_id": item_id,
                    "key_tried": key,
                    "amount_cop": int(amount_cop_pesos),
                    "rail": routing,
                    "execute_response": execute,
                },
            )
        except Exception as e:
            log_event("attention_persist_error", {"error": str(e), "context": "execute_failed"})
        return jsonify({
            "ok": False,
            "error": "execute_failed",
            "message": "Submit a Relampago falló · revisar Trueno manualmente",
            "detail": execute,
        })

    # Extract transaction info del response
    txn = execute.get("data", {}).get("data", {}).get("transaction", {})
    relampago_tx_id = txn.get("id")
    external_id = txn.get("externalId")
    state = txn.get("state", "unknown")

    # Persistir en SQLite para audit + cross-reference futura
    payee = txn.get("payee", {})
    ba = payee.get("bankAccount", {})
    try:
        storage.record_sent_dispersion(
            kashport_id=item_id,
            kashport_provider_id=item.get("oldvprovider_id"),
            relampago_tx_id=relampago_tx_id,
            external_id=external_id,
            payee_name=payee.get("name"),
            payee_key=ba.get("key") or ba.get("number"),
            payee_doc=payee.get("documentNumber"),
            payee_bank=ba.get("bankName"),
            amount_cop=int(amount_cop_pesos),
            rail=routing,
            initial_state=state,
            request_body={"transfers": [validated]},
            response_body=execute.get("data"),
        )
    except Exception as e:
        log_event("storage_error", {"error": str(e)})

    # ============ Step 3 · NEW FLOW 2026-05-23 · two-phase Kashport finalize ============
    # Pre-fix · mark-paid Kashport INMEDIATAMENTE post-execute_dispersion.
    #          Pero Relampago retorna state='created' inmediato · NO state FINAL.
    #          Kashport recibía "paid" sin garantía Relampago realmente sent.
    #
    # Post-fix · NO mark-paid acá · solo persistir en sent_dispersions (state="created",
    #            kashport_finalized=0, awaiting_since=now).
    #            _do_trueno_sync (cron) poll Relampago state · cuando detect state FINAL
    #            (approved/sent OR rejected/declined) → entonces mark Kashport.
    #
    # Garantías:
    #   · Kashport SOLO recibe paid si Relampago confirma sent realmente
    #   · Kashport SOLO recibe rejected si Relampago confirma declination
    #   · Si Relampago state nunca finaliza · timeout cron escalate operator
    log_event("execute_pending_relampago_final", {
        "item_id": item_id,
        "relampago_tx_id": relampago_tx_id,
        "external_id": external_id,
        "initial_state": state,
        "amount_cop": int(amount_cop_pesos),
    })

    COMPLETED_IDS.add(item_id)  # local in-memory · evitar re-process item esta sesión
    return jsonify({
        "ok": True,
        "phase": "awaiting_relampago_final",
        "message": (
            f"Dispersión enviada · ${amount_cop_pesos:,.0f} → {key} · "
            f"esperando estado final Relampago (vtrx={relampago_tx_id})"
        ),
        "relampago_tx_id": relampago_tx_id,
        "external_id": external_id,
        "state": state,
        "provider": txn.get("provider"),
    })


@app.route("/api/process-vurelo/<tx_id>", methods=["POST"])
def api_process_vurelo(tx_id):
    """
    Procesar UN item del flow Vurelo (backend HAv1 queue) · 2026-05-29.

    Diferencia vs api_process (legacy kashport):
    - Claim atómico via Vurelo backend (previene race entre instances)
    - Lee item de VURELO_CACHE o fetch directo
    - Dispatcha via Relámpago execute_dispersion (KAMIN) · igual al flow viejo
    - record_sent_dispersion con vurelo_tx_id (= tx_id Vurelo trx_xxx)
    - Cron _finalize_pending_kashport_marks luego notifica webhook
      con external_id = tx_id (backend resuelve via findById)
    """
    # Hard guard · submit-once
    if tx_id in PROCESSED_IDS or tx_id in COMPLETED_IDS:
        return jsonify({
            "ok": False,
            "error": "already_processed",
            "message": "Item ya fue procesado en esta sesión",
        })

    # PERSISTENT GUARD (sobrevive restart) · busca si ya hay sent_dispersion con
    # este vurelo_tx_id (cualquier momento previo). Si SÍ existe · skip duplicate.
    try:
        existing_sent = storage.find_sent_by_vurelo_tx_id(tx_id)
        if existing_sent:
            log_event("vurelo_dup_skip_persistent", {
                "tx_id": tx_id,
                "previous_vtrx": existing_sent.get("relampago_tx_id"),
                "previous_ts": existing_sent.get("ts_iso"),
            })
            return jsonify({
                "ok": False,
                "error": "already_dispatched_persistent",
                "message": "Ya existe sent_dispersion para este tx_id · NO re-dispatch",
                "previous_vtrx": existing_sent.get("relampago_tx_id"),
            })
    except Exception as e:
        log_event("dup_check_error", {"tx_id": tx_id, "error": str(e)})

    if not relampago.is_logged_in:
        return jsonify({"ok": False, "error": "not_logged_in"})

    # 1 · Find item · cache o fetch
    items = (VURELO_CACHE.get("data") or {}).get("items", [])
    item = next((v for v in items if v.get("tx_id") == tx_id), None)
    if not item:
        # Re-fetch para tener data fresca
        r = vurelo_queue.pending(limit=200, include_claimed=False)
        if not r.get("ok"):
            return jsonify({"ok": False, "error": "queue_fetch_failed", "detail": r})
        items = r.get("items", [])
        item = next((v for v in items if v.get("tx_id") == tx_id), None)
    if not item:
        return jsonify({"ok": False, "error": "tx_not_in_queue"})

    # 2 · Atomic claim (previene race · 2 instances no procesan misma tx)
    claim_resp = vurelo_queue.claim(tx_id, claimed_by=vurelo_queue.RELAMPAGO_OPERATOR_ID)
    if not claim_resp.get("ok") or not claim_resp.get("claimed"):
        log_event("vurelo_claim_denied", {"tx_id": tx_id, "resp": claim_resp})
        return jsonify({
            "ok": False,
            "error": claim_resp.get("error", "claim_failed"),
            "already_claimed_by": claim_resp.get("already_claimed_by"),
            "message": "Otra instancia Relámpago ya tomó esta tx · skip",
        })

    PROCESSED_IDS.add(tx_id)
    log_event("vurelo_process_start", {"tx_id": tx_id})

    # 3 · Extract dispatch data
    dest = item.get("destination") or {}
    key = dest.get("breb_key")
    amount_cop_pesos = item.get("amount_cop_pesos") or 0
    virtual_amount_cents = item.get("amount_cop_centavos") or int(round(float(amount_cop_pesos) * 100))
    routing = "breb"

    if not key or amount_cop_pesos <= 0:
        # Release claim + error
        vurelo_queue.release_claim(tx_id, reason="missing_key_or_amount")
        PROCESSED_IDS.discard(tx_id)
        return jsonify({"ok": False, "error": "invalid_item_data", "tx": item})

    # 4 · Anti-duplicado / gap check
    rules_check = storage.check_dispersion_rules(key, int(amount_cop_pesos))
    if not rules_check.get("ok"):
        vurelo_queue.release_claim(tx_id, reason=f"rule_blocked:{rules_check.get('reason')}")
        PROCESSED_IDS.discard(tx_id)
        log_event("vurelo_rule_blocked", {"tx_id": tx_id, "reason": rules_check.get("reason")})
        return jsonify({
            "ok": False,
            "rule_blocked": True,
            "reason": rules_check.get("reason"),
            "message": rules_check.get("detail"),
            "wait_seconds": rules_check.get("wait_seconds"),
        })

    # 5 · Validate llave · resolve_payee
    resolve = relampago.resolve_payee(key, virtual_amount_cents, routing=routing)
    if resolve.get("status") == 404:
        # Llave inválida · notify webhook rejected · release no necesario (vamos a rejected definitivo)
        try:
            wh = vurelo_webhook.notify_finalize(
                external_id=tx_id,                # backend strategy 0 · findById(trx_xxx)
                state="rejected",
                relampago_tx_id="",
                kashport_item_id=None,
                kashport_provider_id=item.get("cobre_payment_id"),
                amount_cop=int(amount_cop_pesos),
                reason="payee_key_invalid",
                detail=f"Llave BREB no encontrada · validado vía Relampago API · key={key}",
            )
            log_event("vurelo_payee_invalid_notified", {"tx_id": tx_id, "wh": wh})
        except Exception as e:
            log_event("vurelo_notify_exception", {"tx_id": tx_id, "error": str(e)})
        try:
            storage.add_attention(
                kind="vurelo_payee_invalid",
                severity="warn",
                relampago_tx_id=None,
                external_id=tx_id,
                kashport_provider_id=item.get("cobre_payment_id"),
                payee_name=item.get("description"),
                amount_cop=int(amount_cop_pesos),
                description=f"Llave BREB inválida · {key} · monto ${int(amount_cop_pesos):,.0f} · tx {tx_id}",
                detail_json={"tx_id": tx_id, "key_tried": key, "resolve": resolve.get("data")},
            )
        except Exception:
            pass
        COMPLETED_IDS.add(tx_id)
        return jsonify({
            "ok": False,
            "auto_rejected": True,
            "tx_id": tx_id,
            "key": key,
            "message": "Llave inválida · backend marca rejected + libera hold",
        })
    if not resolve.get("ok"):
        vurelo_queue.release_claim(tx_id, reason=f"resolve_failed:{resolve.get('status')}")
        FAILED_IDS[tx_id] = FAILED_IDS.get(tx_id, 0) + 1
        PROCESSED_IDS.discard(tx_id)
        return jsonify({"ok": False, "error": "resolve_failed", "detail": resolve})

    # 6 · Execute dispersión
    resolve_data = resolve.get("data", {}).get("data", {})
    validated_transfers = resolve_data.get("transfers", [])
    if not validated_transfers:
        vurelo_queue.release_claim(tx_id, reason="no_validated_transfer")
        PROCESSED_IDS.discard(tx_id)
        return jsonify({"ok": False, "error": "no_validated_transfer"})

    validated = validated_transfers[0]
    # Description + reference · usar tx_id Vurelo (canonical) + external_id legacy
    validated["description"] = item.get("external_id") or tx_id
    validated["reference"] = item.get("external_id") or tx_id

    execute = relampago.execute_dispersion([validated])
    log_event("vurelo_execute_attempt", {"tx_id": tx_id, "resp_status": execute.get("status")})

    if not execute.get("ok"):
        # Release claim · operador o auto retry después
        vurelo_queue.release_claim(tx_id, reason=f"execute_failed:status={execute.get('status')}")
        try:
            storage.add_attention(
                kind="vurelo_execute_failed",
                severity="critical",
                relampago_tx_id=None,
                external_id=tx_id,
                kashport_provider_id=item.get("cobre_payment_id"),
                payee_name=item.get("description"),
                amount_cop=int(amount_cop_pesos),
                description=(
                    f"Relampago execute FALLÓ · ${int(amount_cop_pesos):,.0f} → {key} · "
                    f"tx {tx_id} · status={execute.get('status')} · revisar Trueno manualmente"
                ),
                detail_json={"tx_id": tx_id, "key": key, "execute_response": execute},
            )
        except Exception:
            pass
        return jsonify({
            "ok": False,
            "error": "execute_failed",
            "message": "Submit a Relampago falló · claim liberado · reintentable",
            "detail": execute,
        })

    # 7 · Persist sent_dispersion · usa tx_id como kashport_id (semantic reuse · new flow)
    txn = execute.get("data", {}).get("data", {}).get("transaction", {})
    relampago_tx_id = txn.get("id")
    kamin_external_id = txn.get("externalId")
    state = txn.get("state", "unknown")
    payee = txn.get("payee", {})
    ba = payee.get("bankAccount", {})
    try:
        storage.record_sent_dispersion(
            kashport_id=tx_id,                                 # NUEVO FLOW · = Vurelo tx_id
            kashport_provider_id=item.get("cobre_payment_id"), # legacy compat (mm_xxx si existe)
            relampago_tx_id=relampago_tx_id,
            external_id=kamin_external_id,                     # KAMIN tx id (audit)
            payee_name=payee.get("name"),
            payee_key=ba.get("key") or ba.get("number"),
            payee_doc=payee.get("documentNumber"),
            payee_bank=ba.get("bankName"),
            amount_cop=int(amount_cop_pesos),
            rail=routing,
            initial_state=state,
            request_body={"transfers": [validated]},
            response_body=execute.get("data"),
            vurelo_tx_id=tx_id,                                # NUEVO column · explicit Vurelo tx_id
        )
    except Exception as e:
        log_event("vurelo_storage_error", {"error": str(e)})

    log_event("vurelo_execute_pending_final", {
        "tx_id": tx_id,
        "relampago_tx_id": relampago_tx_id,
        "external_id": kamin_external_id,
        "initial_state": state,
        "amount_cop": int(amount_cop_pesos),
    })

    COMPLETED_IDS.add(tx_id)
    return jsonify({
        "ok": True,
        "phase": "awaiting_relampago_final",
        "tx_id": tx_id,
        "relampago_tx_id": relampago_tx_id,
        "external_id": kamin_external_id,
        "state": state,
        "message": (
            f"Dispersión enviada · ${amount_cop_pesos:,.0f} → {key} · "
            f"esperando estado final Relampago (vtrx={relampago_tx_id})"
        ),
    })


@app.route("/api/reject/<item_id>", methods=["POST"])
def api_reject(item_id):
    """
    Manual reject desde UI · 2026-05-29 · notifica DIRECTO al backend Vurelo
    (NO Kashport · bypass total). item_id = Vurelo tx_id (trx_xxx) o legacy
    Kashport queue item id (UI nueva siempre envía trx_xxx · legacy mantiene
    compat).

    Backend:
      - Strategy 0 · findById(trx_xxx) match
      - Release hold + mark REJECTED
      - User app ve tx finalizada · saldo restaurado
    """
    body = request.get_json(force=True, silent=True) or {}
    reason = body.get("reason") or "manual_reject_ops"
    detail = body.get("detail") or f"Rechazado manualmente desde UI Relámpago · item={item_id}"

    # Notify Vurelo webhook
    try:
        wh = vurelo_webhook.notify_finalize(
            external_id=item_id,   # trx_xxx · backend strategy 0 findById
            state="rejected",
            relampago_tx_id="",
            kashport_item_id=None,
            kashport_provider_id=None,
            amount_cop=int(body.get("amount_cop") or 0),
            reason=reason,
            detail=detail,
        )
    except Exception as e:
        log_event("manual_reject_exception", {"item_id": item_id, "error": str(e)})
        return jsonify({"ok": False, "error": "webhook_exception", "detail": str(e)})

    log_event("manual_reject_vurelo", {
        "tx_id": item_id,
        "reason": reason,
        "detail": detail[:200],
        "webhook_ok": wh.get("ok"),
        "webhook_status": wh.get("status"),
    })

    if wh.get("ok"):
        COMPLETED_IDS.add(item_id)

    # Audit attention item
    try:
        storage.add_attention(
            kind="manual_reject_vurelo",
            severity="info",
            relampago_tx_id=None,
            external_id=item_id,
            kashport_provider_id=None,
            payee_name=None,
            amount_cop=body.get("amount_cop"),
            description=f"Manual reject Vurelo backend · tx={item_id} · reason={reason}",
            detail_json={
                "tx_id": item_id,
                "reason": reason,
                "detail": detail,
                "webhook_response": wh,
            },
        )
    except Exception as e:
        log_event("attention_persist_error", {"error": str(e), "context": "manual_reject_vurelo"})

    return jsonify({
        "ok": bool(wh.get("ok")),
        "tx_id": item_id,
        "webhook": wh,
        "message": "Tx marcada REJECTED en backend Vurelo · hold liberado · user ve tx finalizada" if wh.get("ok") else "Webhook FALLÓ · revisar logs",
    })


@app.route("/api/ops/recent-events")
def api_ops_recent_events():
    """Service endpoint · x-api-key auth · expone EVENT_LOG en memoria para debug."""
    limit = int(request.args.get("limit", "200"))
    grep = request.args.get("grep", "").lower()
    items = list(EVENT_LOG[-limit:])
    if grep:
        items = [e for e in items if grep in e.get("kind","").lower() or grep in str(e.get("payload","")).lower()]
    return jsonify({"ok": True, "count": len(items), "items": items})


@app.route("/api/ops/recent-sent")
def api_ops_recent_sent():
    """Service endpoint · x-api-key auth · lista sent_dispersions recientes."""
    limit = int(request.args.get("limit", "20"))
    vurelo_tx_id = request.args.get("vurelo_tx_id")
    import sqlite3
    try:
        conn = sqlite3.connect(storage.DB_PATH)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        try:
            cur.execute("ALTER TABLE sent_dispersions ADD COLUMN vurelo_tx_id TEXT")
        except Exception:
            pass
        if vurelo_tx_id:
            rows = cur.execute("SELECT * FROM sent_dispersions WHERE vurelo_tx_id = ? OR kashport_id = ? ORDER BY ts_epoch DESC LIMIT ?", (vurelo_tx_id, vurelo_tx_id, limit)).fetchall()
        else:
            rows = cur.execute("SELECT * FROM sent_dispersions ORDER BY ts_epoch DESC LIMIT ?", (limit,)).fetchall()
        items = [dict(r) for r in rows]
        conn.close()
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})
    return jsonify({"ok": True, "count": len(items), "items": items})


@app.route("/api/ops/recent-rejects")
def api_ops_recent_rejects():
    """
    Service endpoint · x-api-key auth · lista attention_items con kind LIKE
    'manual_reject%' de los últimos N minutos · para que backend identifique
    qué txs marcó el operador como rechazadas.
    """
    minutes = int(request.args.get("minutes", "30"))
    cutoff = time.time() - (minutes * 60)
    import sqlite3
    rows = []
    try:
        conn = sqlite3.connect(storage.DB_PATH)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        result = cur.execute("""
            SELECT id, ts_iso, ts_epoch, kind, severity,
                   relampago_tx_id, external_id, kashport_provider_id,
                   payee_name, amount_cop, description, detail_json
            FROM attention_items
            WHERE kind LIKE 'manual_reject%'
              AND ts_epoch >= ?
            ORDER BY ts_epoch DESC
        """, (cutoff,))
        for r in result.fetchall():
            d = dict(r)
            # detail_json es TEXT · parse
            try:
                d["detail"] = json.loads(d.pop("detail_json") or "{}")
            except Exception:
                d["detail"] = {}
            rows.append(d)
        conn.close()
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})
    return jsonify({"ok": True, "count": len(rows), "items": rows})


@app.route("/api/sent")
def api_sent():
    """Lista de dispersiones enviadas vía esta app (persistidas en SQLite)."""
    return jsonify({"items": storage.list_sent_dispersions(limit=100)})


@app.route("/api/trueno")
def api_trueno():
    """Última snapshot de transacciones Trueno (sync background cada 60s)."""
    state_filter = request.args.get("state")
    return jsonify({"items": storage.list_trueno_transactions(state=state_filter, limit=200)})


@app.route("/api/attention")
def api_attention():
    """Items que requieren atención · ej. rejected_after_sent."""
    only_open = request.args.get("open", "1") == "1"
    return jsonify({"items": storage.list_attention(only_open=only_open, limit=100)})


@app.route("/api/attention/<int:attn_id>/ack", methods=["POST"])
def api_attention_ack(attn_id):
    storage.acknowledge_attention(attn_id)
    return jsonify({"ok": True})


@app.route("/api/stats")
def api_stats():
    return jsonify(storage.stats())


@app.route("/api/sync-trueno", methods=["POST"])
def api_sync_trueno():
    """Force pull de /account/transactions?accountType=Trueno · update DB."""
    result = _do_trueno_sync()
    return jsonify(result)


@app.route("/api/auto", methods=["POST"])
def api_auto_toggle():
    body = request.get_json(force=True, silent=True) or {}
    enabled = bool(body.get("enabled"))
    AUTO_MODE["enabled"] = enabled
    # Persistir en app_settings para sobrevivir restart del service
    storage.set_setting("auto_mode", "1" if enabled else "0")
    log_event("auto_mode_changed", {"enabled": enabled, "persisted": True})
    if enabled:
        _start_auto_loop()
        # Vurelo poller arranca siempre (independiente · UI lo necesita)
        if QUEUE_SOURCE == "vurelo" and vurelo_queue.is_configured():
            _start_vurelo_poller()
        elif QUEUE_SOURCE == "kashport":
            _start_kashport_poller()
    else:
        _auto_stop.set()
        # Solo paramos auto loop · vurelo poller sigue alimentando UI
        if QUEUE_SOURCE == "kashport":
            _kashport_stop.set()
    return jsonify({"ok": True, "enabled": enabled, "persisted": True})


@app.route("/api/events")
def api_events():
    return jsonify({"events": EVENT_LOG[-100:]})


# ============ Auto mode background loop ============

_auto_thread = None
_auto_stop = threading.Event()

# ============ Kashport queue poller (siempre activo) ============

KASHPORT_CACHE = {
    "ok": False,
    "data": None,           # {items, count, today}
    "fetched_at": None,     # ISO timestamp
    "fetched_epoch": None,
    "consecutive_errors": 0,
    "error": None,
    "last_item_count": 0,   # para detectar cambios
}

_kashport_thread = None
_kashport_stop = threading.Event()
KASHPORT_POLL_INTERVAL = 30  # seconds · configurable


def _start_kashport_poller():
    """2026-05-29 · LEGACY REMOVED · ya no se usa Kashport queue (bypass total).
    Mantenido como no-op para que rutas legacy que lo invoquen no crasheen."""
    log_event("kashport_poller_legacy_skipped", {"reason": "vurelo_only_mode"})
    return


# ============ Vurelo backend queue poller · 2026-05-29 · NEW ============

_vurelo_thread = None
_vurelo_stop = threading.Event()
VURELO_POLL_INTERVAL = int(os.environ.get("VURELO_POLL_INTERVAL", "30"))


def _start_vurelo_poller():
    global _vurelo_thread
    if _vurelo_thread and _vurelo_thread.is_alive():
        return
    _vurelo_stop.clear()
    _vurelo_thread = threading.Thread(target=_vurelo_poller_loop, daemon=True, name="vurelo-poller")
    _vurelo_thread.start()
    log_event("vurelo_poller_started", {"interval_s": VURELO_POLL_INTERVAL})


def _vurelo_poller_loop():
    """
    Poller Vurelo backend BREB cashout queue · ACTIVO SIEMPRE (no requiere
    Relampago session activa). UI lee de VURELO_CACHE.
    Auto loop usa cache para procesar items.
    Si vurelo_queue no configurado · skip silencioso (log error N veces).
    """
    while not _vurelo_stop.is_set():
        if not vurelo_queue.is_configured():
            VURELO_CACHE["error"] = "not_configured · faltan VURELO_API_BASE_URL o VURELO_SERVICE_API_KEY"
            VURELO_CACHE["consecutive_errors"] += 1
            if VURELO_CACHE["consecutive_errors"] in (1, 10, 60):
                log_event("vurelo_queue_not_configured", {
                    "count": VURELO_CACHE["consecutive_errors"],
                })
        else:
            try:
                r = vurelo_queue.pending(limit=100, include_claimed=False)
                if r.get("ok"):
                    new_count = r.get("total", 0)
                    prev_count = VURELO_CACHE.get("last_item_count", 0)
                    VURELO_CACHE.update({
                        "ok": True,
                        "data": {"items": r.get("items", []), "count": new_count},
                        "fetched_at": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime()),
                        "fetched_epoch": time.time(),
                        "consecutive_errors": 0,
                        "error": None,
                        "last_item_count": new_count,
                    })
                    if new_count != prev_count:
                        log_event("vurelo_queue_changed", {
                            "prev": prev_count, "now": new_count, "delta": new_count - prev_count,
                        })
                else:
                    VURELO_CACHE["consecutive_errors"] += 1
                    VURELO_CACHE["error"] = r.get("error") or r.get("body")
                    if VURELO_CACHE["consecutive_errors"] in (3, 10, 30):
                        log_event("vurelo_poll_errors", {
                            "count": VURELO_CACHE["consecutive_errors"],
                            "error": VURELO_CACHE["error"],
                        })
            except Exception as e:
                VURELO_CACHE["consecutive_errors"] += 1
                VURELO_CACHE["error"] = str(e)
        if _vurelo_stop.wait(VURELO_POLL_INTERVAL):
            break


def _kashport_poller_loop():
    """2026-05-29 · LEGACY REMOVED · ya no se usa Kashport queue (bypass total).
    Si por error se llama, exit inmediato."""
    log_event("kashport_poller_loop_legacy_skipped", {"reason": "vurelo_only_mode"})
    return


def _start_auto_loop():
    global _auto_thread
    if _auto_thread and _auto_thread.is_alive():
        return
    _auto_stop.clear()
    _auto_thread = threading.Thread(target=_auto_loop, daemon=True, name="auto-process")
    _auto_thread.start()


def _auto_loop():
    """
    Loop que procesa items pending automáticamente desde Vurelo backend queue.
    2026-05-29 · LEGACY Kashport polling REMOVIDO · single source = Vurelo backend.
    Claim atómico en backend previene race entre instances + restart.
    """
    POLL_INTERVAL = 15  # segundos
    while not _auto_stop.is_set():
        if not AUTO_MODE["enabled"]:
            break
        if not relampago.is_logged_in:
            time.sleep(5)
            continue

        try:
            items = (VURELO_CACHE.get("data") or {}).get("items") or []
            if not items:
                r = vurelo_queue.pending(limit=100, include_claimed=False)
                if r.get("ok"):
                    items = r.get("items", [])
            for it in items:
                if not AUTO_MODE["enabled"]:
                    break
                tx_id = it.get("tx_id")
                if not tx_id or tx_id in PROCESSED_IDS or tx_id in COMPLETED_IDS:
                    continue
                if FAILED_IDS.get(tx_id, 0) >= 1:
                    continue
                # Guard adicional · si backend ya marcó claimed (otra instance) · skip
                if (it.get("claim") or {}).get("claimed"):
                    continue
                log_event("auto_processing_vurelo", {"tx_id": tx_id})
                with app.test_request_context():
                    api_process_vurelo(tx_id)
        except Exception as e:
            log_event("auto_error", {"error": str(e)})

        if _auto_stop.wait(POLL_INTERVAL):
            break


# ============ Trueno sync · poll periódico ============

_trueno_thread = None
_trueno_stop = threading.Event()


def _do_trueno_sync():
    """Trae /account/transactions?accountType=Trueno y persiste en DB. Detecta rejected.
    2026-05-23 · refactor · usa relampago.get_trueno_transactions() · NO acceso direct a session.
    2026-05-23 · NEW · finalize Kashport SOLO cuando Relampago state final detectado."""
    result = relampago.get_trueno_transactions()
    if not result.get("ok"):
        if result.get("error") == "not_logged_in":
            return result
        log_event("trueno_sync_error", {"error": result.get("error") or f"http_{result.get('status')}"})
        return result
    try:
        transfers = result["data"].get("transfers", [])
        for t in transfers:
            storage.upsert_trueno_transaction(t)
        # Cross-reference (detecta rejected_after_sent)
        new_attns = storage.cross_reference_sent_vs_trueno()
        # NEW · finalize Kashport para sent_dispersions awaiting + state final detectado
        finalized = _finalize_pending_kashport_marks()
        log_event("trueno_sync", {
            "count": len(transfers),
            "new_attention": new_attns,
            "kashport_finalized": finalized,
        })
        return {"ok": True, "count": len(transfers), "new_attention": new_attns, "kashport_finalized": finalized}
    except Exception as e:
        log_event("trueno_sync_error", {"error": str(e)})
        return {"ok": False, "error": str(e)}


# ============ Two-phase Kashport finalize · 2026-05-23 · NEW ============

# Relampago states · clasificación final
# Approved/sent · transferencia completada con éxito
# Rejected/declined · transferencia rechazada por Relampago/destino
# Created/pending · aún en flight · NO finalize todavía
RELAMPAGO_STATES_FINAL_OK = {"approved", "sent", "executed", "completed", "settled"}
RELAMPAGO_STATES_FINAL_FAIL = {"rejected", "declined", "failed", "cancelled", "canceled"}


def _finalize_pending_kashport_marks() -> dict:
    """
    Procesa sent_dispersions con kashport_finalized=0 ·
    si Relampago state es final · mark Kashport correspondiente.

    Returns · {marked_paid: N, marked_rejected: N, still_awaiting: N, errors: [...]}
    """
    awaiting = storage.list_awaiting_kashport_finalize()
    out = {"marked_paid": 0, "marked_rejected": 0, "still_awaiting": 0, "errors": []}

    for record in awaiting:
        vtrx_id = record.get("relampago_tx_id")
        kashport_id = record.get("kashport_id")
        if not vtrx_id or not kashport_id:
            continue

        # Lookup state en trueno_transactions (sync source)
        try:
            trueno_rows = storage.list_trueno_transactions(state=None, limit=10000)
            trueno_match = next(
                (t for t in trueno_rows if t.get("transaction_id") == vtrx_id),
                None,
            )
        except Exception as e:
            out["errors"].append({"vtrx": vtrx_id, "error": f"lookup_failed: {e}"})
            continue

        if not trueno_match:
            # vtrx aún NO aparece en trueno_sync · still pending
            out["still_awaiting"] += 1
            continue

        state = (trueno_match.get("state") or "").lower()
        declination = trueno_match.get("declination_reason")

        if state in RELAMPAGO_STATES_FINAL_OK:
            # 2026-05-29 · BYPASS Kashport answer · solo notify Vurelo webhook.
            # Para flow Vurelo nuevo · pasa vurelo_tx_id como external_id (backend
            # resuelve via findById strategy 0). Para flow legacy Kashport · pasa
            # external_id (KAMIN) + kashport_provider_id (mm_xxx).
            primary_external_id = record.get("vurelo_tx_id") or record.get("external_id") or ""
            try:
                wh = vurelo_webhook.notify_finalize(
                    external_id=str(primary_external_id),
                    state="approved",
                    relampago_tx_id=vtrx_id,
                    kashport_item_id=str(kashport_id),
                    kashport_provider_id=record.get("kashport_provider_id"),
                    amount_cop=int(record.get("amount_cop") or 0),
                )
                if wh.get("ok"):
                    # IDEMPOTENT · marca local SQLite que ya cerramos este vtrx
                    if storage.mark_kashport_finalized(vtrx_id, "paid"):
                        out["marked_paid"] += 1
                        log_event("vurelo_finalized_paid", {
                            "kashport_id": kashport_id,
                            "relampago_tx_id": vtrx_id,
                            "state": state,
                            "amount_cop": record.get("amount_cop"),
                            "webhook_status": wh.get("status"),
                        })
                else:
                    out["errors"].append({
                        "vtrx": vtrx_id,
                        "action": "vurelo_webhook_paid_failed",
                        "webhook_response": wh,
                    })
                    log_event("vurelo_webhook_paid_failed", {
                        "kashport_id": kashport_id,
                        "relampago_tx_id": vtrx_id,
                        "webhook": wh,
                    })
                    # Attention item · operador revisa
                    try:
                        storage.add_attention(
                            kind="vurelo_webhook_paid_failed",
                            severity="critical",
                            relampago_tx_id=vtrx_id,
                            external_id=record.get("external_id"),
                            kashport_provider_id=record.get("kashport_provider_id"),
                            payee_name=record.get("payee_name"),
                            amount_cop=record.get("amount_cop"),
                            description=(
                                f"Vurelo webhook approved FALLÓ · Relampago sent OK · "
                                f"${record.get('amount_cop'):,.0f} · saga BREB_CASHOUT NO cerrado"
                            ),
                            detail_json={
                                "kashport_id": kashport_id,
                                "vtrx_id": vtrx_id,
                                "webhook_response": wh,
                                "relampago_state": state,
                            },
                        )
                    except Exception:
                        pass
            except Exception as e:
                out["errors"].append({"vtrx": vtrx_id, "error": f"vurelo_webhook_paid_exception: {e}"})

        elif state in RELAMPAGO_STATES_FINAL_FAIL:
            # FINAL FAIL · mark Kashport rejected con motivo real Relampago
            try:
                reason = declination or "rejected_by_relampago"
                detail = f"Relampago state={state} · declination={declination or 'sin detalle'}"
                # 2026-05-29 · BYPASS Kashport · solo notify Vurelo webhook
                primary_external_id = record.get("vurelo_tx_id") or record.get("external_id") or ""
                try:
                    wh = vurelo_webhook.notify_finalize(
                        external_id=str(primary_external_id),
                        state="rejected",
                        relampago_tx_id=vtrx_id,
                        kashport_item_id=str(kashport_id),
                        kashport_provider_id=record.get("kashport_provider_id"),
                        amount_cop=int(record.get("amount_cop") or 0),
                        reason=reason,
                        detail=detail,
                    )
                    if wh.get("ok"):
                        if storage.mark_kashport_finalized(vtrx_id, "rejected"):
                            out["marked_rejected"] += 1
                            log_event("vurelo_finalized_rejected", {
                                "kashport_id": kashport_id,
                                "relampago_tx_id": vtrx_id,
                                "state": state,
                                "declination": declination,
                                "amount_cop": record.get("amount_cop"),
                                "webhook_status": wh.get("status"),
                            })
                    else:
                        out["errors"].append({
                            "vtrx": vtrx_id,
                            "action": "vurelo_webhook_rejected_failed",
                            "webhook_response": wh,
                        })
                        log_event("vurelo_webhook_rejected_failed", {
                            "kashport_id": kashport_id,
                            "relampago_tx_id": vtrx_id,
                            "webhook": wh,
                        })
                        try:
                            storage.add_attention(
                                kind="vurelo_webhook_rejected_failed",
                                severity="critical",
                                relampago_tx_id=vtrx_id,
                                external_id=record.get("external_id"),
                                kashport_provider_id=record.get("kashport_provider_id"),
                                payee_name=record.get("payee_name"),
                                amount_cop=record.get("amount_cop"),
                                description=(
                                    f"Vurelo webhook rejected FALLÓ · Relampago decline OK "
                                    f"pero saga HAv1 sin cerrar · revisar release hold"
                                ),
                                detail_json={
                                    "kashport_id": kashport_id,
                                    "vtrx_id": vtrx_id,
                                    "webhook_response": wh,
                                    "relampago_state": state,
                                    "declination": declination,
                                },
                            )
                        except Exception:
                            pass
                except Exception as e:
                    out["errors"].append({"vtrx": vtrx_id, "error": f"vurelo_webhook_rejected_exception: {e}"})

                # Attention item para audit · severity warn (operator review)
                try:
                    storage.add_attention(
                        kind="rejected_by_relampago_async",
                        severity="warn",
                        relampago_tx_id=vtrx_id,
                        external_id=record.get("external_id"),
                        kashport_provider_id=record.get("kashport_provider_id"),
                        payee_name=record.get("payee_name"),
                        amount_cop=record.get("amount_cop"),
                        description=(
                            f"Relampago rechazó dispersión · ${record.get('amount_cop'):,.0f} "
                            f"· state={state} · {declination or 'sin detalle'}"
                        ),
                        detail_json={
                            "vtrx_id": vtrx_id,
                            "kashport_id": kashport_id,
                            "state": state,
                            "declination": declination,
                            "trueno_match": trueno_match,
                        },
                    )
                except Exception:
                    pass
            except Exception as e:
                out["errors"].append({"vtrx": vtrx_id, "error": f"finalize_rejected_exception: {e}"})

        else:
            # state intermedio (created · pending · etc) · still awaiting
            out["still_awaiting"] += 1

    return out


def _trueno_sync_loop():
    POLL_INTERVAL = 60  # cada 60s
    while not _trueno_stop.is_set():
        if relampago.is_logged_in:
            _do_trueno_sync()
        if _trueno_stop.wait(POLL_INTERVAL):
            break


def _start_trueno_sync():
    global _trueno_thread
    if _trueno_thread and _trueno_thread.is_alive():
        return
    _trueno_stop.clear()
    _trueno_thread = threading.Thread(target=_trueno_sync_loop, daemon=True, name="trueno-sync")
    _trueno_thread.start()


# Arrancar sync loop después del primer login OK
# (lo hacemos en el endpoint login_mfa hook)
_original_login_mfa = api_login_mfa


# ============ Startup / Shutdown ============

def _startup(args):
    """Restaurar estado · cookies + auto_mode · health check."""
    # 1. Cargar Kashport token persistido
    saved_kashport = storage.get_setting("kashport_token", "")
    if saved_kashport:
        kashport.set_token(saved_kashport)
        print("✓ Kashport token cargado de SQLite")

    # 2. Restaurar sesión Relampago
    restored = relampago.restore_from_storage()
    session_alive = False
    if restored:
        print(f"⏳ Cookies restauradas (email={relampago._last_login_email}) · verificando...")
        session_alive = relampago.verify_session_alive()
        if session_alive:
            print(f"✓ Sesión Relampago VIVA · refresh count={relampago._refresh_count}")
            _start_trueno_sync()
        else:
            print("✗ Sesión Relampago muerta · UI pedirá re-login")
    else:
        print("· Sin sesión previa · UI pedirá login")

    # 3. Resolver auto_mode (CLI flag > DB > default manual)
    if args.auto:
        AUTO_MODE["enabled"] = True
        storage.set_setting("auto_mode", "1")
        print("▶ AUTO mode FORZADO por CLI flag --auto")
    elif args.manual:
        AUTO_MODE["enabled"] = False
        storage.set_setting("auto_mode", "0")
        print("· MANUAL mode FORZADO por CLI flag --manual")
    else:
        saved = storage.get_setting("auto_mode", "0")
        AUTO_MODE["enabled"] = saved == "1"
        print(f"· Modo restaurado de SQLite · {'AUTO' if AUTO_MODE['enabled'] else 'MANUAL'}")

    # 4. Arrancar Vurelo backend poller SIEMPRE (UI necesita queue independiente
    # del auto_mode · single source of truth = Vurelo backend HAv1).
    # Solo si QUEUE_SOURCE=vurelo (default) · si legacy kashport no se arranca.
    if QUEUE_SOURCE == "vurelo":
        if vurelo_queue.is_configured():
            _start_vurelo_poller()
            print(f"▶ Vurelo backend poller arrancado · interval={VURELO_POLL_INTERVAL}s")
        else:
            print("⚠ QUEUE_SOURCE=vurelo · pero VURELO_API_BASE_URL/VURELO_SERVICE_API_KEY no configurados")

    # 5. Si auto + session alive · arrancar auto loop + (legacy) kashport poller
    if AUTO_MODE["enabled"] and session_alive:
        _start_auto_loop()
        if QUEUE_SOURCE == "kashport":
            _start_kashport_poller()
            print("▶ AUTO loop + Kashport poller arrancados (legacy mode)")
        else:
            print(f"▶ AUTO loop arrancado (queue={QUEUE_SOURCE})")
    elif AUTO_MODE["enabled"] and not session_alive:
        print("⚠ AUTO mode ON pero session muerta · loops arrancarán tras login")

    return session_alive


def _shutdown_handler(signum, frame):
    print("\n· SIGTERM recibido · graceful shutdown...")
    try:
        if relampago.is_logged_in:
            relampago.persist_to_storage()
            print("✓ Sesión final persistida a SQLite")
    except Exception as e:
        print(f"✗ Error al persistir · {e}")
    _auto_stop.set()
    _trueno_stop.set()
    _vurelo_stop.set()
    sys.exit(0)


def _cli_status():
    """Imprime status del service (sin arrancar Flask)."""
    sess = storage.load_session()
    auto = storage.get_setting("auto_mode", "0") == "1"
    ks_set = bool(storage.get_setting("kashport_token", ""))
    print("=" * 50)
    print(f"DB:               {storage.DB_PATH}")
    if sess:
        ttl = (sess.get("token_expires_at") or 0) - time.time()
        print(f"Sesión guardada:  ✓ email={sess['email']} · expira en {int(ttl)}s")
        print(f"  refresh_count:  {sess.get('refresh_count', 0)}")
        print(f"  cookies:        {list(sess['cookies'].keys())}")
    else:
        print("Sesión guardada:  ✗ (necesita login)")
    print(f"Kashport token:   {'✓ configurado' if ks_set else '✗ no configurado'}")
    print(f"Auto mode:        {'AUTO' if auto else 'MANUAL'}")
    print(f"Stats:            {storage.stats()}")
    print("=" * 50)


def _cli_logout():
    """Borra sesión persistida (sin arrancar Flask)."""
    storage.clear_session()
    print("✓ Sesión persistida borrada · próximo arranque pedirá login")


# ============ Run ============

def parse_args():
    ap = argparse.ArgumentParser(description="Vurelo Relampago Operator service")
    ap.add_argument("--auto", action="store_true", help="Forzar AUTO mode al startup")
    ap.add_argument("--manual", action="store_true", help="Forzar MANUAL mode al startup")
    ap.add_argument("--port", type=int, default=int(os.environ.get("PORT", "3000")))
    ap.add_argument("--host", default=os.environ.get("BIND_HOST", "127.0.0.1"),
                    help="Bind host · default 127.0.0.1 local · 0.0.0.0 en Docker")
    ap.add_argument("--no-open", action="store_true", help="No auto-open browser")
    ap.add_argument("--logout", action="store_true", help="Borra sesión persistida y sale")
    ap.add_argument("--status", action="store_true", help="Imprime status y sale")
    args = ap.parse_args()
    if args.auto and args.manual:
        print("✗ --auto y --manual son mutuamente excluyentes")
        sys.exit(1)
    return args


if __name__ == "__main__":
    args = parse_args()

    # Init DB siempre (lo necesitan --status y --logout también)
    storage.init_db()

    if args.status:
        _cli_status()
        sys.exit(0)
    if args.logout:
        _cli_logout()
        sys.exit(0)

    # Startup
    print(f"\n╔══════════════════════════════════════════════════╗")
    print(f"║  Vurelo Relampago Operator · service")
    print(f"║  Port      · {args.port}")
    print(f"║  Auto flag · {args.auto or args.manual}")
    print(f"║  UI        · http://localhost:{args.port}")
    print(f"║  DB        · {storage.DB_PATH}")
    print(f"╚══════════════════════════════════════════════════╝\n")

    session_alive = _startup(args)

    # Signal handlers para graceful shutdown
    signal.signal(signal.SIGTERM, _shutdown_handler)
    signal.signal(signal.SIGINT, _shutdown_handler)

    # Auto-open browser si no se desactiva
    if not args.no_open:
        threading.Timer(1.0, lambda: webbrowser.open(f"http://localhost:{args.port}")).start()

    app.run(host=args.host, port=args.port, debug=False, threaded=True, use_reloader=False)
