"""
Cliente Kashport · operator API (cola manual).
Mismo flow que la Chrome extension v0.3.
"""
import requests

BASE_URL = "https://payments.kashport.com"


class KashportClient:
    def __init__(self, token: str = ""):
        self.token = token

    def set_token(self, token: str):
        self.token = (token or "").strip()

    def _headers(self):
        return {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    @property
    def configured(self) -> bool:
        return bool(self.token)

    def pending(self) -> dict:
        """Lista de items pending (cola del día)."""
        if not self.configured:
            return {"ok": False, "error": "no_token"}
        try:
            r = requests.get(f"{BASE_URL}/api/manual-queue/pending/", headers=self._headers(), timeout=10)
            if r.status_code == 200:
                return {"ok": True, "data": r.json()}
            return {"ok": False, "status": r.status_code, "body": r.text[:300]}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def mark_paid(self, item_id: str, meta: dict = None) -> dict:
        if not self.configured:
            return {"ok": False, "error": "no_token"}
        try:
            r = requests.post(
                f"{BASE_URL}/api/manual-queue/{item_id}/mark-paid/",
                headers=self._headers(),
                json=meta or {},
                timeout=10,
            )
            return {"ok": r.status_code in (200, 201, 204), "status": r.status_code, "body": r.text[:300]}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    def mark_rejected(self, item_id: str, reason: str = "", detail: str = "") -> dict:
        if not self.configured:
            return {"ok": False, "error": "no_token"}
        try:
            r = requests.post(
                f"{BASE_URL}/api/manual-queue/{item_id}/mark-rejected/",
                headers=self._headers(),
                json={"reason": reason, "detail": detail},
                timeout=10,
            )
            return {"ok": r.status_code in (200, 201, 204), "status": r.status_code, "body": r.text[:300]}
        except Exception as e:
            return {"ok": False, "error": str(e)}
