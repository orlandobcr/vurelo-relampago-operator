"""
Persistencia SQLite · 3 tablas:

   sent_dispersions   · lo que NOSOTROS enviamos a Relampago (snapshot del momento)
   trueno_transactions · lo que TRUENO/Relampago reporta (poll periódico de /account/transactions)
   attention_items    · cross-reference · items con discrepancia (sent OK pero rejected en Trueno)

DB file · ~/.vurelo-relampago.db
"""
import json
import os
import sqlite3
import threading
import time
from contextlib import contextmanager

DB_PATH = os.path.expanduser("~/.vurelo-relampago.db")
_lock = threading.RLock()


def _connect():
    conn = sqlite3.connect(DB_PATH, isolation_level=None, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


@contextmanager
def _cursor():
    with _lock:
        c = _connect()
        try:
            yield c
        finally:
            c.close()


def init_db():
    # File perms 600 antes de tocar (solo el usuario lee/escribe)
    if os.path.exists(DB_PATH):
        try:
            os.chmod(DB_PATH, 0o600)
        except Exception:
            pass

    with _cursor() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS app_settings (
            key   TEXT PRIMARY KEY,
            value TEXT,
            updated_at REAL
        );

        CREATE TABLE IF NOT EXISTS session_state (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            cookies_json     TEXT,          -- {name: {value, domain, path}}
            email            TEXT,
            last_refresh     REAL,
            token_expires_at REAL,
            refresh_count    INTEGER DEFAULT 0,
            updated_at       REAL,
            session_started_at REAL         -- 2026-05-23 · Cognito refresh_token age tracking
        );

        CREATE TABLE IF NOT EXISTS balance_thresholds (
            account_type        TEXT PRIMARY KEY,    -- 'OTC-BREB', 'OTC-RAYO', 'OTC', etc
            threshold_cop       REAL NOT NULL,        -- en pesos COP
            enabled             INTEGER NOT NULL DEFAULT 1,
            last_alert_sent_at  REAL,                 -- epoch del último envío
            last_balance_seen   REAL,
            updated_at          REAL
        );

        CREATE TABLE IF NOT EXISTS sent_dispersions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts_iso              TEXT NOT NULL,
            ts_epoch            REAL NOT NULL,
            kashport_id         TEXT,
            kashport_provider_id TEXT,        -- mm_xxx
            relampago_tx_id     TEXT,         -- vtrx_xxx
            external_id         TEXT,         -- KAMIN tx
            payee_name          TEXT,
            payee_key           TEXT,
            payee_doc           TEXT,
            payee_bank          TEXT,
            amount_cop          INTEGER,       -- pesos (no centavos)
            rail                TEXT,
            initial_state       TEXT,         -- "created" típicamente
            current_state       TEXT,         -- updated por trueno sync
            current_declination TEXT,
            request_json        TEXT,
            response_json       TEXT,
            last_state_check    REAL
        );
        CREATE INDEX IF NOT EXISTS idx_sent_relampago_tx ON sent_dispersions(relampago_tx_id);
        CREATE INDEX IF NOT EXISTS idx_sent_external_id  ON sent_dispersions(external_id);
        CREATE INDEX IF NOT EXISTS idx_sent_kashport     ON sent_dispersions(kashport_provider_id);
        CREATE INDEX IF NOT EXISTS idx_sent_ts           ON sent_dispersions(ts_epoch DESC);

        CREATE TABLE IF NOT EXISTS trueno_transactions (
            transaction_id      TEXT PRIMARY KEY,        -- vtrx_xxx
            external_id         TEXT,                    -- provider tx (e.g. KAMIN)
            description         TEXT,                    -- usually contains mm_xxx (Kashport id)
            amount              INTEGER,                 -- siempre negativo (debit)
            routing             TEXT,
            state               TEXT,                    -- approved · rejected · created · etc
            declination_reason  TEXT,
            trx_type            TEXT,                    -- debit · commission_fee_complete · etc
            external_provider   TEXT,                    -- KAMIN
            payee_name          TEXT,
            payee_key           TEXT,
            payee_bank          TEXT,
            payee_doc           TEXT,
            inserted_at_iso     TEXT,
            updated_at_iso      TEXT,
            full_json           TEXT,
            last_seen_epoch     REAL,
            first_seen_epoch    REAL,
            account_type        TEXT DEFAULT 'Trueno'    -- 'Trueno' (BReB) · 'Turbo-ACH' (ACH) · feed de origen
        );
        CREATE INDEX IF NOT EXISTS idx_trueno_state    ON trueno_transactions(state);
        CREATE INDEX IF NOT EXISTS idx_trueno_routing  ON trueno_transactions(routing);
        CREATE INDEX IF NOT EXISTS idx_trueno_acctype  ON trueno_transactions(account_type);
        CREATE INDEX IF NOT EXISTS idx_trueno_desc     ON trueno_transactions(description);
        CREATE INDEX IF NOT EXISTS idx_trueno_external ON trueno_transactions(external_id);

        CREATE TABLE IF NOT EXISTS attention_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts_iso              TEXT NOT NULL,
            ts_epoch            REAL NOT NULL,
            kind                TEXT NOT NULL,           -- 'rejected_after_sent', 'fallback_used', etc
            severity            TEXT NOT NULL,           -- 'critical' · 'warn' · 'info'
            relampago_tx_id     TEXT,
            external_id         TEXT,
            kashport_provider_id TEXT,
            payee_name          TEXT,
            amount_cop          INTEGER,
            description         TEXT,
            detail_json         TEXT,
            acknowledged        INTEGER DEFAULT 0,       -- 0/1 · operador puede marcar como visto
            acknowledged_at     TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_attn_ack       ON attention_items(acknowledged);
        CREATE INDEX IF NOT EXISTS idx_attn_severity  ON attention_items(severity);
        """)

    # Migración 2026-06-17 · columna account_type en DBs existentes (separa
    # Trueno=BReB de Turbo-ACH=ACH). Guarded · si ya existe, ignora.
    with _cursor() as c:
        cols = [r[1] for r in c.execute("PRAGMA table_info(trueno_transactions)").fetchall()]
        if "account_type" not in cols:
            c.execute("ALTER TABLE trueno_transactions ADD COLUMN account_type TEXT DEFAULT 'Trueno'")
            c.execute("CREATE INDEX IF NOT EXISTS idx_trueno_acctype ON trueno_transactions(account_type)")

    # Seed thresholds default si NO existen (no override si el user ya editó)
    with _cursor() as c:
        defaults = [
            ("OTC-BREB", 150_000_000),   # Trueno · 150M COP
            ("OTC-RAYO", 70_000_000),    # Turbo · 70M COP
            ("OTC",      50_000_000),    # OTC general · 50M default
        ]
        for acc_type, default_thr in defaults:
            existing = c.execute(
                "SELECT account_type FROM balance_thresholds WHERE account_type = ?",
                (acc_type,)
            ).fetchone()
            if not existing:
                c.execute("""
                    INSERT INTO balance_thresholds
                    (account_type, threshold_cop, enabled, updated_at)
                    VALUES (?, ?, 1, ?)
                """, (acc_type, default_thr, time.time()))

    # Seed reglas de dispersión default
    if get_setting("dispersion_min_gap_seconds") is None:
        set_setting("dispersion_min_gap_seconds", "15")
    if get_setting("dispersion_same_payee_window_minutes") is None:
        set_setting("dispersion_same_payee_window_minutes", "10")

    # Seed alert recipients default
    if not get_setting("alert_recipients"):
        defaults_emails = [
            "andres.fajardo@vureloapp.co",
            "camilo.suarez@vureloapp.com",
            "alejo.celis@vureloapp.com",
        ]
        set_setting("alert_recipients", json.dumps(defaults_emails))

    # ============ Migration · 2026-05-23 · two-phase Kashport finalize ============
    # New flow · NO mark_paid Kashport inmediato post-execute_dispersion.
    # Wait until trueno_sync detect Relampago state FINAL (approved/sent OR rejected).
    # Solo entonces · kashport.mark_paid o mark_rejected.
    # Columns para tracking:
    #   · kashport_finalized · 0/1 · si Kashport ya marcado
    #   · kashport_finalize_action · 'paid' | 'rejected' | NULL
    #   · kashport_finalize_at · timestamp ISO cuando se marcó
    #   · awaiting_since · epoch cuando entró a estado awaiting (para timeout)
    with _cursor() as c:
        for ddl in [
            "ALTER TABLE sent_dispersions ADD COLUMN kashport_finalized INTEGER DEFAULT 0",
            "ALTER TABLE sent_dispersions ADD COLUMN kashport_finalize_action TEXT",
            "ALTER TABLE sent_dispersions ADD COLUMN kashport_finalize_at TEXT",
            "ALTER TABLE sent_dispersions ADD COLUMN awaiting_since REAL",
            "CREATE INDEX IF NOT EXISTS idx_sent_awaiting ON sent_dispersions(kashport_finalized, awaiting_since)",
        ]:
            try:
                c.execute(ddl)
            except Exception:
                pass  # column / index ya existe


# ============ app_settings (key/value) ============

def get_setting(key: str, default=None):
    with _cursor() as c:
        row = c.execute("SELECT value FROM app_settings WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else default


def set_setting(key: str, value: str):
    with _cursor() as c:
        c.execute("""
            INSERT INTO app_settings (key, value, updated_at) VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
        """, (key, value, time.time()))


def delete_setting(key: str):
    with _cursor() as c:
        c.execute("DELETE FROM app_settings WHERE key = ?", (key,))


# ============ session_state (single-row · upsert) ============

def save_session(cookies: dict, email: str, last_refresh: float,
                 token_expires_at: float, refresh_count: int,
                 session_started_at: float = None):
    """Persist session state to SQLite (single row, id=1).
    2026-05-23 · session_started_at agregado para tracking Cognito refresh_token TTL.
    Auto-add column si schema viejo (migration in-place)."""
    with _cursor() as c:
        # In-place migration · agregar column si NO existe (idempotente)
        try:
            c.execute("ALTER TABLE session_state ADD COLUMN session_started_at REAL")
        except Exception:
            pass  # column ya existe
        c.execute("""
            INSERT INTO session_state
            (id, cookies_json, email, last_refresh, token_expires_at, refresh_count, updated_at, session_started_at)
            VALUES (1, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                cookies_json       = excluded.cookies_json,
                email              = excluded.email,
                last_refresh       = excluded.last_refresh,
                token_expires_at   = excluded.token_expires_at,
                refresh_count      = excluded.refresh_count,
                updated_at         = excluded.updated_at,
                session_started_at = COALESCE(excluded.session_started_at, session_state.session_started_at)
        """, (json.dumps(cookies, default=str), email, last_refresh, token_expires_at,
              refresh_count, time.time(), session_started_at))


def load_session() -> dict:
    with _cursor() as c:
        # In-place migration · agregar column si NO existe (idempotente · safe en restart)
        try:
            c.execute("ALTER TABLE session_state ADD COLUMN session_started_at REAL")
        except Exception:
            pass  # column ya existe
        row = c.execute("SELECT * FROM session_state WHERE id = 1").fetchone()
        if not row:
            return None
        keys = row.keys()
        return {
            "cookies": json.loads(row["cookies_json"]) if row["cookies_json"] else {},
            "email": row["email"],
            "last_refresh": row["last_refresh"],
            "token_expires_at": row["token_expires_at"],
            "refresh_count": row["refresh_count"] or 0,
            "updated_at": row["updated_at"],
            "session_started_at": row["session_started_at"] if "session_started_at" in keys else None,
        }


def clear_session():
    with _cursor() as c:
        c.execute("DELETE FROM session_state WHERE id = 1")


# ============ sent_dispersions ============

def record_sent_dispersion(
    kashport_id: str,
    kashport_provider_id: str,
    relampago_tx_id: str,
    external_id: str,
    payee_name: str,
    payee_key: str,
    payee_doc: str,
    payee_bank: str,
    amount_cop: int,
    rail: str,
    initial_state: str,
    request_body: dict,
    response_body: dict,
    vurelo_tx_id: str = None,
):
    """2026-05-23 · awaiting_since seteado · kashport_finalized=0 default.
    Kashport mark happens later · cuando trueno_sync detect estado final Relampago.
    2026-05-29 · vurelo_tx_id NEW · flow Vurelo backend (sin Kashport intermedio)."""
    now = time.time()
    iso = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now))
    # Migration on-the-fly · agregar columna vurelo_tx_id si no existe (SQLite no soporta IF NOT EXISTS en ALTER)
    with _cursor() as c:
        try:
            c.execute("ALTER TABLE sent_dispersions ADD COLUMN vurelo_tx_id TEXT")
        except Exception:
            pass  # ya existe
        try:
            c.execute("CREATE INDEX IF NOT EXISTS idx_sent_vurelo_tx ON sent_dispersions(vurelo_tx_id)")
        except Exception:
            pass
        c.execute("""
            INSERT INTO sent_dispersions
            (ts_iso, ts_epoch, kashport_id, kashport_provider_id,
             relampago_tx_id, external_id, payee_name, payee_key, payee_doc, payee_bank,
             amount_cop, rail, initial_state, current_state,
             request_json, response_json, last_state_check,
             kashport_finalized, awaiting_since, vurelo_tx_id)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            iso, now, kashport_id, kashport_provider_id,
            relampago_tx_id, external_id, payee_name, payee_key, payee_doc, payee_bank,
            amount_cop, rail, initial_state, initial_state,
            json.dumps(request_body, default=str), json.dumps(response_body, default=str), now,
            0, now, vurelo_tx_id,
        ))


def get_sent_by_relampago_tx(relampago_tx_id: str) -> dict | None:
    """2026-05-23 · lookup sent_dispersion por vtrx_id · retorna None si no existe."""
    with _cursor() as c:
        row = c.execute("""
            SELECT * FROM sent_dispersions WHERE relampago_tx_id = ? LIMIT 1
        """, (relampago_tx_id,)).fetchone()
        return dict(row) if row else None


def get_sent_by_kashport_id(kashport_id: str) -> dict | None:
    """2026-05-23 · lookup por kashport_id · útil dedup pre-execute."""
    with _cursor() as c:
        row = c.execute("""
            SELECT * FROM sent_dispersions WHERE kashport_id = ? LIMIT 1
        """, (kashport_id,)).fetchone()
        return dict(row) if row else None


def find_sent_by_vurelo_tx_id(vurelo_tx_id: str):
    """2026-05-29 · check si ya despachamos este tx_id (Vurelo flow).
    Crítico para prevenir doble dispatch tras container restart."""
    if not vurelo_tx_id:
        return None
    with _cursor() as c:
        # Auto-migration · idempotent
        try:
            c.execute("ALTER TABLE sent_dispersions ADD COLUMN vurelo_tx_id TEXT")
        except Exception:
            pass
        row = c.execute("""
            SELECT id, ts_iso, relampago_tx_id, current_state, amount_cop
            FROM sent_dispersions
            WHERE vurelo_tx_id = ?
            ORDER BY ts_epoch DESC LIMIT 1
        """, (vurelo_tx_id,)).fetchone()
        return dict(row) if row else None


def list_awaiting_kashport_finalize() -> list:
    """2026-05-23 · sent_dispersions sin kashport_finalized=0 · listas para evaluar finalize.
    2026-05-29 · expone vurelo_tx_id si existe (flow nuevo · backend lookup directo)."""
    with _cursor() as c:
        # Auto-migration · agregar vurelo_tx_id si no existe (idempotent)
        try:
            c.execute("ALTER TABLE sent_dispersions ADD COLUMN vurelo_tx_id TEXT")
        except Exception:
            pass
        rows = c.execute("""
            SELECT * FROM sent_dispersions
            WHERE kashport_finalized = 0
            ORDER BY awaiting_since ASC
        """).fetchall()
        return [dict(r) for r in rows]


def mark_kashport_finalized(relampago_tx_id: str, action: str) -> bool:
    """2026-05-23 · marca Kashport finalize done · IDEMPOTENT.
    action · 'paid' | 'rejected'
    Solo UPDATE si kashport_finalized=0 actualmente · prevents double-mark race.
    Returns True si efectivamente actualizó · False si ya estaba marcado."""
    iso = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())
    with _cursor() as c:
        cur = c.execute("""
            UPDATE sent_dispersions
            SET kashport_finalized = 1,
                kashport_finalize_action = ?,
                kashport_finalize_at = ?
            WHERE relampago_tx_id = ? AND kashport_finalized = 0
        """, (action, iso, relampago_tx_id))
        return cur.rowcount > 0


def list_stale_awaiting(hours: int = 6) -> list:
    """2026-05-23 · sent_dispersions awaiting > N hours · escalation candidates."""
    cutoff = time.time() - (hours * 3600)
    with _cursor() as c:
        rows = c.execute("""
            SELECT * FROM sent_dispersions
            WHERE kashport_finalized = 0
              AND awaiting_since IS NOT NULL
              AND awaiting_since < ?
            ORDER BY awaiting_since ASC
        """, (cutoff,)).fetchall()
        return [dict(r) for r in rows]


def list_sent_dispersions(limit: int = 100) -> list:
    with _cursor() as c:
        rows = c.execute("""
            SELECT * FROM sent_dispersions
            ORDER BY ts_epoch DESC
            LIMIT ?
        """, (limit,)).fetchall()
        return [dict(r) for r in rows]


def update_sent_state(relampago_tx_id: str, new_state: str, declination_reason: str = None):
    with _cursor() as c:
        c.execute("""
            UPDATE sent_dispersions
            SET current_state = ?, current_declination = ?, last_state_check = ?
            WHERE relampago_tx_id = ?
        """, (new_state, declination_reason, time.time(), relampago_tx_id))


# ============ trueno_transactions (snapshot from Relampago) ============

def upsert_trueno_transaction(txn: dict, account_type: str = "Trueno"):
    """
    Inserta o actualiza una tx tal como la reportó Relampago.
    txn · objeto del array /v0/account/transactions?accountType=<account_type>
    account_type · 'Trueno' (BReB) o 'Turbo-ACH' (ACH) · separa las listas en UI.
    """
    tx_id = txn.get("transactionId")
    if not tx_id:
        return
    payee = txn.get("payee") or {}
    ba = payee.get("bankAccount") or {}
    now = time.time()

    with _cursor() as c:
        existing = c.execute("SELECT first_seen_epoch FROM trueno_transactions WHERE transaction_id = ?", (tx_id,)).fetchone()
        first_seen = existing["first_seen_epoch"] if existing else now
        c.execute("""
            INSERT OR REPLACE INTO trueno_transactions
            (transaction_id, external_id, description, amount, routing, state,
             declination_reason, trx_type, external_provider,
             payee_name, payee_key, payee_bank, payee_doc,
             inserted_at_iso, updated_at_iso, full_json,
             last_seen_epoch, first_seen_epoch, account_type)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            tx_id,
            txn.get("externalTransactionId"),
            txn.get("description"),
            txn.get("amount"),
            txn.get("routing"),
            txn.get("state"),
            txn.get("declinationReason"),
            txn.get("trxType"),
            txn.get("externalProvider"),
            payee.get("name"),
            ba.get("key"),
            ba.get("bankName"),
            payee.get("documentNumber"),
            txn.get("inserted_at"),
            txn.get("updated_at"),
            json.dumps(txn, default=str),
            now, first_seen, account_type,
        ))


def list_trueno_transactions(state: str = None, limit: int = 200, account_type: str = None) -> list:
    """account_type · 'Trueno' (BReB) | 'Turbo-ACH' (ACH) | None (todas).
    El finalize llama con account_type=None (matchea por tx id, agnóstico al rail).
    La UI separa las listas pasando account_type."""
    clauses, params = [], []
    if state:
        clauses.append("state = ?"); params.append(state)
    if account_type:
        # COALESCE · filas legacy sin account_type cuentan como 'Trueno' (BReB)
        clauses.append("COALESCE(account_type, 'Trueno') = ?"); params.append(account_type)
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(limit)
    with _cursor() as c:
        rows = c.execute(
            f"SELECT * FROM trueno_transactions{where} ORDER BY inserted_at_iso DESC LIMIT ?",
            tuple(params),
        ).fetchall()
        return [dict(r) for r in rows]


# ============ attention_items ============

def add_attention(kind: str, severity: str, **kwargs):
    """
    Agregar un item de atención · ej. 'rejected_after_sent'.
    kwargs · relampago_tx_id, external_id, kashport_provider_id, payee_name,
            amount_cop, description, detail_json (dict)
    """
    now = time.time()
    iso = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now))
    detail = kwargs.get("detail_json")
    if isinstance(detail, dict):
        detail = json.dumps(detail, default=str)
    with _cursor() as c:
        # Evitar duplicados · si ya hay attention activa para esta tx + kind · skip
        existing = c.execute("""
            SELECT id FROM attention_items
            WHERE kind = ? AND relampago_tx_id = ? AND acknowledged = 0
        """, (kind, kwargs.get("relampago_tx_id"))).fetchone()
        if existing:
            return existing["id"]
        cur = c.execute("""
            INSERT INTO attention_items
            (ts_iso, ts_epoch, kind, severity, relampago_tx_id, external_id,
             kashport_provider_id, payee_name, amount_cop, description, detail_json)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
        """, (
            iso, now, kind, severity,
            kwargs.get("relampago_tx_id"),
            kwargs.get("external_id"),
            kwargs.get("kashport_provider_id"),
            kwargs.get("payee_name"),
            kwargs.get("amount_cop"),
            kwargs.get("description"),
            detail,
        ))
        return cur.lastrowid


def list_attention(only_open: bool = True, limit: int = 100) -> list:
    with _cursor() as c:
        if only_open:
            rows = c.execute(
                "SELECT * FROM attention_items WHERE acknowledged = 0 ORDER BY severity, ts_epoch DESC LIMIT ?",
                (limit,),
            ).fetchall()
        else:
            rows = c.execute(
                "SELECT * FROM attention_items ORDER BY ts_epoch DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]


def acknowledge_attention(attn_id: int):
    with _cursor() as c:
        c.execute(
            "UPDATE attention_items SET acknowledged = 1, acknowledged_at = ? WHERE id = ?",
            (time.strftime("%Y-%m-%dT%H:%M:%S"), attn_id),
        )


# ============ cross-reference logic ============

def cross_reference_sent_vs_trueno():
    """
    Detecta items que NOSOTROS enviamos pero ahora Trueno reporta como rejected.
    Genera attention_items 'rejected_after_sent' con severity critical.

    También · actualiza current_state de sent_dispersions con el state real.
    """
    new_attns = 0
    with _cursor() as c:
        # Para cada sent_dispersion · buscar la txn correspondiente en Trueno
        sent = c.execute("""
            SELECT s.relampago_tx_id, s.external_id, s.kashport_provider_id,
                   s.payee_name, s.amount_cop, s.initial_state, s.current_state
            FROM sent_dispersions s
        """).fetchall()
        for row in sent:
            tx_id = row["relampago_tx_id"]
            if not tx_id:
                continue
            trueno = c.execute("""
                SELECT transaction_id, state, declination_reason, description, amount
                FROM trueno_transactions
                WHERE transaction_id = ?
            """, (tx_id,)).fetchone()
            if not trueno:
                continue

            # Update current_state si cambió
            new_state = trueno["state"]
            if new_state != row["current_state"]:
                c.execute("""
                    UPDATE sent_dispersions
                    SET current_state = ?, current_declination = ?, last_state_check = ?
                    WHERE relampago_tx_id = ?
                """, (new_state, trueno["declination_reason"], time.time(), tx_id))

            # ALERTA · rejected
            if new_state in ("rejected", "declined", "failed", "returned"):
                attn_id = add_attention(
                    kind="rejected_after_sent",
                    severity="critical",
                    relampago_tx_id=tx_id,
                    external_id=row["external_id"],
                    kashport_provider_id=row["kashport_provider_id"],
                    payee_name=row["payee_name"],
                    amount_cop=row["amount_cop"],
                    description=f"Tx enviada a {row['payee_name']} · Trueno la rechazó · {trueno['declination_reason'] or 'sin razón'}",
                    detail_json={
                        "trueno_state": new_state,
                        "declination_reason": trueno["declination_reason"],
                        "initial_state_at_send": row["initial_state"],
                        "amount_cop": row["amount_cop"],
                    },
                )
                if attn_id:
                    new_attns += 1
    return new_attns


# ============ balance_thresholds ============

def list_thresholds() -> list:
    with _cursor() as c:
        rows = c.execute("SELECT * FROM balance_thresholds ORDER BY account_type").fetchall()
        return [dict(r) for r in rows]


def get_threshold(account_type: str) -> dict:
    with _cursor() as c:
        row = c.execute(
            "SELECT * FROM balance_thresholds WHERE account_type = ?", (account_type,)
        ).fetchone()
        return dict(row) if row else None


def set_threshold(account_type: str, threshold_cop: float, enabled: bool = True):
    with _cursor() as c:
        c.execute("""
            INSERT INTO balance_thresholds
                (account_type, threshold_cop, enabled, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(account_type) DO UPDATE SET
                threshold_cop = excluded.threshold_cop,
                enabled       = excluded.enabled,
                updated_at    = excluded.updated_at
        """, (account_type, float(threshold_cop), 1 if enabled else 0, time.time()))


def mark_alert_sent(account_type: str, balance_at_alert: float):
    with _cursor() as c:
        c.execute("""
            UPDATE balance_thresholds
            SET last_alert_sent_at = ?, last_balance_seen = ?, updated_at = ?
            WHERE account_type = ?
        """, (time.time(), balance_at_alert, time.time(), account_type))


def reset_alert_state(account_type: str):
    """Cuando el saldo VUELVE arriba del threshold · reset · próximo alert vuelve a salir."""
    with _cursor() as c:
        c.execute("""
            UPDATE balance_thresholds
            SET last_alert_sent_at = NULL, updated_at = ?
            WHERE account_type = ?
        """, (time.time(), account_type))


# ============ dispersion rules check ============

def check_dispersion_rules(payee_key: str, amount_cop: int) -> dict:
    """
    Pre-flight check antes de enviar a Relampago.
    Reglas:
      1. Min gap global · NO dispersar si la última fue hace < N segundos
      2. Anti-duplicado · NO dispersar al mismo payee_key con el mismo amount_cop
         dentro de una ventana de M minutos (BREB lo bloquea)
    Retorna · {ok: True} o {ok: False, reason, wait_seconds?, detail?}
    """
    gap_s = int(get_setting("dispersion_min_gap_seconds", "15") or "15")
    window_min = int(get_setting("dispersion_same_payee_window_minutes", "10") or "10")
    now = time.time()

    with _cursor() as c:
        # Check 1 · global min gap
        row = c.execute("SELECT MAX(ts_epoch) AS last_ts FROM sent_dispersions").fetchone()
        if row and row["last_ts"]:
            elapsed = now - row["last_ts"]
            if elapsed < gap_s:
                return {
                    "ok": False,
                    "reason": "min_gap",
                    "wait_seconds": round(gap_s - elapsed, 1),
                    "detail": f"Última dispersión hace {elapsed:.1f}s · espera {gap_s - elapsed:.1f}s más (min gap {gap_s}s)",
                }

        # Check 2 · misma firma (payee_key + amount_cop) en ventana
        window_start = now - (window_min * 60)
        same = c.execute("""
            SELECT id, ts_iso, ts_epoch, payee_name, relampago_tx_id
            FROM sent_dispersions
            WHERE payee_key = ? AND amount_cop = ? AND ts_epoch > ?
            ORDER BY ts_epoch DESC
            LIMIT 1
        """, (payee_key, int(amount_cop), window_start)).fetchone()
        if same:
            minutes_ago = (now - same["ts_epoch"]) / 60
            return {
                "ok": False,
                "reason": "duplicate_payee_amount",
                "detail": f"Ya enviada misma combinación (payee {payee_key} + monto exacto ${amount_cop:,.0f}) hace {minutes_ago:.1f} min · BREB bloquearía · espera {window_min - minutes_ago:.1f} min más o cambia el monto",
                "last_sent_at": same["ts_iso"],
                "last_tx_id": same["relampago_tx_id"],
                "minutes_ago": round(minutes_ago, 1),
                "window_min": window_min,
            }

    return {"ok": True, "min_gap_seconds": gap_s, "window_minutes": window_min}


# ============ summary stats ============

def stats():
    with _cursor() as c:
        sent_count = c.execute("SELECT COUNT(*) FROM sent_dispersions").fetchone()[0]
        sent_today = c.execute("SELECT COUNT(*) FROM sent_dispersions WHERE ts_epoch > ?",
                               (time.time() - 86400,)).fetchone()[0]
        trueno_count = c.execute("SELECT COUNT(*) FROM trueno_transactions").fetchone()[0]
        trueno_rejected = c.execute("SELECT COUNT(*) FROM trueno_transactions WHERE state = 'rejected'").fetchone()[0]
        attn_open = c.execute("SELECT COUNT(*) FROM attention_items WHERE acknowledged = 0").fetchone()[0]
        attn_critical = c.execute(
            "SELECT COUNT(*) FROM attention_items WHERE acknowledged = 0 AND severity = 'critical'"
        ).fetchone()[0]
        return {
            "sent_total": sent_count,
            "sent_today": sent_today,
            "trueno_total": trueno_count,
            "trueno_rejected": trueno_rejected,
            "attention_open": attn_open,
            "attention_critical": attn_critical,
            "db_path": DB_PATH,
        }
