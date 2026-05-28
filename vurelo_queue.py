"""
Vurelo backend BREB cashout queue · 2026-05-28.

Reemplaza el polling de Cobre/Kashport queue · Relámpago app ahora se
conecta DIRECTO al backend Vurelo HAv1 (api.vurelo.co) para obtener las
tx BREB cashout PENDING. Single source of truth = backend HAv1 DB.

Flow:
  1. pending(limit) · GET /admin/relampago/pending-dispersions
  2. claim(tx_id, claimed_by) · POST /admin/relampago/claim-dispersion (atomic)
  3. (Relámpago dispatches KAMIN externally)
  4. release_claim(tx_id) si dispatch falla y queremos reintentar
  5. (notify_finalize vía vurelo_webhook.py cuando llegue state final)

Envs requeridas:
  VURELO_API_BASE_URL   = https://api.vurelo.co
  VURELO_SERVICE_API_KEY = clave service (la misma SERVICE_API_KEY del backend)
  VURELO_API_TIMEOUT     = default 10s
  RELAMPAGO_OPERATOR_ID  = identificador propio (e.g. "relampago-w1" o "relampago-auto")
"""
import os
import time
from typing import Any, Dict, Optional

import requests


VURELO_API_BASE_URL = os.environ.get("VURELO_API_BASE_URL", "https://api.vurelo.co").rstrip("/")
VURELO_SERVICE_API_KEY = os.environ.get("VURELO_SERVICE_API_KEY", "")
VURELO_API_TIMEOUT = float(os.environ.get("VURELO_API_TIMEOUT", "10"))
RELAMPAGO_OPERATOR_ID = os.environ.get("RELAMPAGO_OPERATOR_ID", "relampago-app")


def is_configured() -> bool:
    """True si tenemos URL Y api key · sino el módulo skip silencioso."""
    return bool(VURELO_API_BASE_URL and VURELO_SERVICE_API_KEY)


def _headers() -> Dict[str, str]:
    return {
        "Content-Type": "application/json",
        "x-api-key": VURELO_SERVICE_API_KEY,
        "User-Agent": "vurelo-relampago/0.5",
    }


def pending(limit: int = 50, include_claimed: bool = False) -> Dict[str, Any]:
    """
    GET /admin/relampago/pending-dispersions

    Returns:
      {ok: bool, items: [...], total: int, error?: str, status?: int}
    """
    if not is_configured():
        return {"ok": False, "error": "not_configured", "items": [], "total": 0}

    params = {"limit": str(limit)}
    if include_claimed:
        params["include_claimed"] = "true"
    try:
        r = requests.get(
            f"{VURELO_API_BASE_URL}/api/v1/admin/relampago/pending-dispersions",
            headers=_headers(),
            params=params,
            timeout=VURELO_API_TIMEOUT,
        )
        if r.status_code != 200:
            return {
                "ok": False,
                "status": r.status_code,
                "error": "non_200",
                "body": r.text[:400],
                "items": [],
                "total": 0,
            }
        data = r.json()
        return {
            "ok": data.get("ok", True),
            "items": data.get("items", []),
            "total": data.get("total", len(data.get("items", []))),
        }
    except requests.RequestException as e:
        return {"ok": False, "error": "request_exception", "detail": str(e)[:200], "items": [], "total": 0}


def claim(tx_id: str, claimed_by: Optional[str] = None, relampago_tx_id: Optional[str] = None) -> Dict[str, Any]:
    """
    POST /admin/relampago/claim-dispersion

    Atomic claim · si ya está tomada por otra instancia · returns ok=False
    con error='already_claimed' y already_claimed_by=<otro_id>.

    Args:
      tx_id           · trx_xxx (Vurelo tx id)
      claimed_by      · default RELAMPAGO_OPERATOR_ID
      relampago_tx_id · opcional · si ya tenemos vtrx pre-asignado

    Returns:
      {ok: bool, claimed: bool, tx_id: str, error?: str, already_claimed_by?: str}
    """
    if not is_configured():
        return {"ok": False, "error": "not_configured"}
    if not tx_id:
        return {"ok": False, "error": "tx_id required"}

    body = {
        "tx_id": tx_id,
        "claimed_by": claimed_by or RELAMPAGO_OPERATOR_ID,
    }
    if relampago_tx_id:
        body["relampago_tx_id"] = relampago_tx_id
    try:
        r = requests.post(
            f"{VURELO_API_BASE_URL}/api/v1/admin/relampago/claim-dispersion",
            headers=_headers(),
            json=body,
            timeout=VURELO_API_TIMEOUT,
        )
        try:
            data = r.json()
        except Exception:
            data = {"ok": False, "error": f"non-JSON response · status={r.status_code}"}
        return data
    except requests.RequestException as e:
        return {"ok": False, "error": "request_exception", "detail": str(e)[:200]}


def release_claim(tx_id: str, claimed_by: Optional[str] = None, reason: str = "manual_release") -> Dict[str, Any]:
    """
    POST /admin/relampago/release-claim

    Libera claim si dispatch KAMIN falló · para reintentar.
    Solo el claimed_by original puede liberar (sanity check backend).
    """
    if not is_configured():
        return {"ok": False, "error": "not_configured"}
    if not tx_id:
        return {"ok": False, "error": "tx_id required"}
    body = {
        "tx_id": tx_id,
        "claimed_by": claimed_by or RELAMPAGO_OPERATOR_ID,
        "reason": reason,
    }
    try:
        r = requests.post(
            f"{VURELO_API_BASE_URL}/api/v1/admin/relampago/release-claim",
            headers=_headers(),
            json=body,
            timeout=VURELO_API_TIMEOUT,
        )
        try:
            return r.json()
        except Exception:
            return {"ok": False, "error": f"non-JSON status={r.status_code}"}
    except requests.RequestException as e:
        return {"ok": False, "error": "request_exception", "detail": str(e)[:200]}


def dispersion_status(recent_limit: int = 20) -> Dict[str, Any]:
    """
    GET /admin/relampago/dispersion-status

    Para UI seguimiento · counts + recent tx.
    """
    if not is_configured():
        return {"ok": False, "error": "not_configured"}
    try:
        r = requests.get(
            f"{VURELO_API_BASE_URL}/api/v1/admin/relampago/dispersion-status",
            headers=_headers(),
            params={"recent_limit": str(recent_limit)},
            timeout=VURELO_API_TIMEOUT,
        )
        try:
            return r.json()
        except Exception:
            return {"ok": False, "error": f"non-JSON status={r.status_code}"}
    except requests.RequestException as e:
        return {"ok": False, "error": "request_exception", "detail": str(e)[:200]}
