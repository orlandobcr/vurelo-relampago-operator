"""
Notifier · envío de alertas vía SMTP (Amazon SES · DigitALL).

SMTP creds están en código (mismas que el user proveyó · DigitALL SES).
Si quieres rotarlas · cambia las constantes O usa env vars:
   VURELO_SMTP_USER · VURELO_SMTP_PASS
"""
import json
import os
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr

try:
    import storage
except ImportError:
    storage = None

SMTP_HOST = "email-smtp.us-east-1.amazonaws.com"
SMTP_PORT = 587
SMTP_USER = os.environ.get("VURELO_SMTP_USER") or "AKIAYAECALAB6GUHOLWT"
SMTP_PASS = os.environ.get("VURELO_SMTP_PASS") or "BGDRIgfBYVMMwXkOroyhxkeXJ4wGV7kOfcNiDd09iKYk"
FROM_NAME = "DigitALL Automate"
FROM_EMAIL = "no-reply@digitall.io"


def get_recipients() -> list:
    """Lee la lista de emails de alerta del SQLite."""
    if storage is None:
        return []
    raw = storage.get_setting("alert_recipients", "[]")
    try:
        return json.loads(raw)
    except Exception:
        return []


def set_recipients(emails: list):
    """Persiste la lista de emails."""
    if storage is None:
        return
    cleaned = [e.strip() for e in emails if e and "@" in e]
    storage.set_setting("alert_recipients", json.dumps(cleaned))


def send_email(subject: str, html_body: str, text_body: str = None, to: list = None) -> dict:
    """
    Envía un email a la lista de recipients (o `to` custom).
    Retorna · {ok, recipients_count, error?}
    """
    recipients = to if to else get_recipients()
    if not recipients:
        return {"ok": False, "error": "no_recipients"}

    msg = MIMEMultipart("alternative")
    msg["From"] = formataddr((FROM_NAME, FROM_EMAIL))
    msg["To"] = ", ".join(recipients)
    msg["Subject"] = subject

    if text_body:
        msg.attach(MIMEText(text_body, "plain", "utf-8"))
    msg.attach(MIMEText(html_body, "html", "utf-8"))

    try:
        ctx = ssl.create_default_context()
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as srv:
            srv.starttls(context=ctx)
            srv.login(SMTP_USER, SMTP_PASS)
            srv.sendmail(FROM_EMAIL, recipients, msg.as_string())
        return {"ok": True, "recipients_count": len(recipients), "recipients": recipients}
    except Exception as e:
        return {"ok": False, "error": str(e), "type": type(e).__name__}


# ============ Alerta saldo bajo ============

ACCOUNT_DISPLAY_NAME = {
    "OTC-BREB": "Saldo Trueno (BREB)",
    "OTC-RAYO": "Saldo Turbo (Rayo)",
    "OTC":      "Saldo OTC general",
}


def fmt_cop(amount):
    try:
        return f"$ {amount:,.0f} COP"
    except Exception:
        return f"$ {amount}"


def send_low_balance_alert(account_type: str, account_id: str, current_balance: float, threshold: float) -> dict:
    """
    Envía alerta de saldo bajo · en español · a recipients configurados.
    Retorna resultado del send_email.
    """
    display = ACCOUNT_DISPLAY_NAME.get(account_type, account_type)
    diff = threshold - current_balance
    pct = (current_balance / threshold * 100) if threshold > 0 else 0

    subject = f"⚠ Alerta Vurelo · saldo bajo en {display}"

    html = f"""
    <html>
    <body style="font-family: -apple-system, sans-serif; color: #1f2937; background: #f8fafc; padding: 20px;">
      <div style="max-width: 580px; margin: 0 auto; background: white; border-radius: 10px; padding: 28px; box-shadow: 0 1px 3px rgba(0,0,0,0.1);">
        <h1 style="color: #b91c1c; margin: 0 0 6px;">⚠ Saldo bajo · acción requerida</h1>
        <p style="color: #6b7280; margin: 0 0 22px;">Alerta automática del Vurelo Relampago Operator.</p>

        <div style="background: #fef2f2; border-left: 4px solid #b91c1c; padding: 14px 18px; border-radius: 6px;">
          <div style="font-size: 12px; color: #6b7280; letter-spacing: 0.05em; text-transform: uppercase;">{display}</div>
          <div style="font-size: 28px; font-weight: 700; color: #b91c1c; margin: 6px 0;">{fmt_cop(current_balance)}</div>
          <div style="font-size: 14px; color: #6b7280;">
            Umbral configurado · <strong>{fmt_cop(threshold)}</strong><br>
            Está <strong>{fmt_cop(diff)}</strong> por debajo · {pct:.1f}% del umbral
          </div>
        </div>

        <h3 style="color: #1f2937; margin-top: 24px;">Acción recomendada</h3>
        <p>Recargar la cuenta <strong>{display}</strong> (account · <code style="background: #f1f5f9; padding: 2px 6px; border-radius: 3px;">{account_id}</code>) antes de que se agote y las dispersiones empiecen a fallar.</p>

        <p style="color: #6b7280; font-size: 12px; margin-top: 30px; padding-top: 16px; border-top: 1px solid #e5e7eb;">
          Esta es una alerta automática · solo se envía una vez por evento de saldo bajo.<br>
          Para silenciar, ajusta el umbral o desactiva las alertas en el panel del operador.<br>
          <em>Vurelo Relampago Operator · DigitALL Automate</em>
        </p>
      </div>
    </body>
    </html>
    """

    text = (
        f"Saldo bajo en {display}\n\n"
        f"Saldo actual · {fmt_cop(current_balance)}\n"
        f"Umbral · {fmt_cop(threshold)}\n"
        f"Por debajo · {fmt_cop(diff)} ({pct:.1f}% del umbral)\n\n"
        f"Account · {account_id}\n\n"
        f"Acción · recargar la cuenta antes de que se agote.\n"
        f"Esta alerta solo se envía una vez por evento."
    )

    return send_email(subject, html, text)


def send_test_email() -> dict:
    """Envía un email de prueba a los recipients · útil para validar config."""
    html = """
    <html><body style="font-family: sans-serif; padding: 20px;">
      <h2>✓ Test email · Vurelo Relampago Operator</h2>
      <p>Si recibes esto, las alertas están configuradas correctamente.</p>
      <p style="color: #6b7280; font-size: 12px;">Sent via DigitALL SMTP (Amazon SES)</p>
    </body></html>
    """
    return send_email("Test · Vurelo Relampago Operator", html, "Test email · alertas OK")
