"""
Vurelo webhook · notifica al backend HAv1 el cierre final del flow BREB.

Llamado desde _finalize_pending_kashport_marks() en server.py después de
marcar Kashport (mark_paid o mark_rejected) correctamente. Cierra el saga
BREB_CASHOUT del backend Vurelo (api.vurelo.co) que de otra forma quedaría
esperando la respuesta de Kashport.

Envs requeridas (con default por compat):
  VURELO_WEBHOOK_URL     = https://api.vurelo.co/api/v1/webhooks/payments/relampago-result
  VURELO_WEBHOOK_SECRET  = HMAC SHA256 key (mismo que backend Coolify env
                           RELAMPAGO_WEBHOOK_SECRET)

Firma:
  x-vurelo-signature = HMAC_SHA256(body_json, VURELO_WEBHOOK_SECRET) en hex
"""
import hashlib
import hmac
import json
import os
import time
from typing import Any, Dict, Optional

import requests


VURELO_WEBHOOK_URL = os.environ.get(
    "VURELO_WEBHOOK_URL",
    "https://api.vurelo.co/api/v1/webhooks/payments/relampago-result",
)
VURELO_WEBHOOK_SECRET = os.environ.get("VURELO_WEBHOOK_SECRET", "")
VURELO_WEBHOOK_TIMEOUT = float(os.environ.get("VURELO_WEBHOOK_TIMEOUT", "10"))


def is_configured() -> bool:
    """True solo si tenemos URL Y secret · sino skip silencioso (log)."""
    return bool(VURELO_WEBHOOK_URL and VURELO_WEBHOOK_SECRET)


def _sign(body_bytes: bytes) -> str:
    return hmac.new(
        VURELO_WEBHOOK_SECRET.encode("utf-8"),
        body_bytes,
        hashlib.sha256,
    ).hexdigest()


def notify_finalize(
    external_id: str,
    state: str,
    relampago_tx_id: str,
    kashport_item_id: Optional[str] = None,
    amount_cop: Optional[int] = None,
    reason: Optional[str] = None,
    detail: Optional[str] = None,
) -> Dict[str, Any]:
    """
    POST al webhook Vurelo con firma HMAC.

    Args:
        external_id      · oldvprovider_id Kashport · ÚNICO required (= tx Vurelo).
        state            · 'approved' | 'rejected'.
        relampago_tx_id  · vtrx_xxx · audit.
        kashport_item_id · audit.
        amount_cop       · int · audit.
        reason/detail    · opcional para rejected.

    Returns:
        {ok: bool, status: int, body: str, error: str | None}
    """
    if not is_configured():
        return {
            "ok": False,
            "error": "not_configured",
            "detail": "VURELO_WEBHOOK_URL or VURELO_WEBHOOK_SECRET missing",
        }

    if state not in ("approved", "rejected"):
        return {"ok": False, "error": "invalid_state", "detail": f"state={state}"}

    payload = {
        "external_id": external_id,
        "relampago_tx_id": relampago_tx_id or "",
        "kashport_item_id": kashport_item_id,
        "amount_cop": amount_cop,
        "state": state,
        "reason": reason,
        "detail": detail,
        "finalized_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    # JSON canonical · sin spaces · separators=(',', ':') · garantiza que
    # backend re-serialice match (NestJS no reorder keys). Si tuviéramos
    # ordering issues, usar sorted keys.
    body_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    signature = _sign(body_bytes)

    headers = {
        "Content-Type": "application/json",
        "x-vurelo-signature": signature,
        "User-Agent": "vurelo-relampago/0.4",
    }

    try:
        r = requests.post(
            VURELO_WEBHOOK_URL,
            data=body_bytes,
            headers=headers,
            timeout=VURELO_WEBHOOK_TIMEOUT,
        )
        return {
            "ok": r.status_code in (200, 202),
            "status": r.status_code,
            "body": r.text[:500],
        }
    except requests.RequestException as e:
        return {"ok": False, "error": "request_exception", "detail": str(e)[:200]}
    except Exception as e:
        return {"ok": False, "error": "unexpected", "detail": str(e)[:200]}
