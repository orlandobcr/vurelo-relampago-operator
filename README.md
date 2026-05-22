# Vurelo Relampago Operator

App web standalone para procesar dispersiones desde la cola Kashport usando la API directa de Relampago (sin Chrome extension).

## Qué hace

```
1. Login Relampago · email + password + PIN TOTP (6 dígitos)
2. Sesión persistente · refresh automático cada 9 min en background
3. Dashboard con:
   · Saldos Vurelo (OTC-BREB · OTC · OTC-RAYO)
   · Cola Kashport pending (mismo endpoint que la Chrome extension v0.3)
   · Modo MANUAL · click "▶ Procesar" item por item (default)
   · Modo AUTO opcional · procesa todo automático cada 15s
4. Auto-validate de llave BREB vía /transactions/resolve-payee
   · Si llave inválida · auto-mark-rejected (refund al user)
5. Event log en vivo · todas las acciones visibles
```

## Diferencias vs Chrome extension

| Aspecto | Chrome Extension v0.3 | App standalone |
|---|---|---|
| Dispersa via | DOM scraping en Trueno UI | API directa `/transactions/execute` |
| Detect llave inválida | Toast DOM detection | HTTP 404 de `/resolve-payee` |
| Sesión Relampago | Cookie del browser | Refresh loop Python |
| Sesión Kashport | Token operador | Mismo · token operador |
| Submit guard | chrome.storage.local | In-memory set |
| Falla DOM marker | Bug 2-ter potencial | NO existe (sin DOM) |

## Instalación

```bash
cd ~/Downloads/relampago-vurelo-app
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 server.py
```

UI · http://localhost:8787

## Flujo de uso

```
1. Abrir http://localhost:8787
2. Login: otc@vureloapp.com + password
3. PIN: 6 dígitos del TOTP
4. Dashboard se carga · ves saldos
5. (Una vez) Pega el token operador Kashport · "Guardar token"
6. Items pending aparecen · procesa manualmente o activa AUTO
7. Sesión se mantiene viva indefinidamente mientras corra el server
```

## Endpoints API (interno · UI los usa)

```
POST /api/login/password      · paso 1 login
POST /api/login/mfa           · paso 2 MFA · PIN
POST /api/logout
POST /api/refresh             · forzar refresh sesión

GET  /api/status              · status sesión + auto mode
GET  /api/balance             · saldos
GET  /api/bank-codes          · catálogo bancos
GET  /api/transactions        · historial Relampago

POST /api/kashport/token      · configurar token
GET  /api/queue               · cola pending Kashport

POST /api/process/<id>        · procesar una dispersión
POST /api/reject/<id>         · rechazar manualmente
POST /api/auto                · toggle AUTO mode
GET  /api/events              · log de eventos
```

## Notas técnicas · auth flow descubierto

```
Cognito User Pool · us-east-1_QSCc8rWNl
Client ID · 22349hus625pj1n8fro75672na (confidential · con secret)
Hosted UI · https://auth.relampago-pay.io
Callback · https://portal.relampago-pay.io/auth/callback

Flow:
   GET  /login                          → CSRF + cookies
   POST /login {username, password}     → 302 a /mfa/totp
   GET  /mfa/totp                       → CSRF nuevo
   POST /mfa/totp {code}                → 302 a portal/auth/callback?code=XXX
   POST /v0/auth/exchange {authorizationCode} → Set-Cookie access_token

Refresh:
   POST /v0/auth/refresh {}             → rota access_token + session_id
   Cookies: access_token (Max-Age 600) · session_id (Max-Age 3600)
   Server bloquea refresh si token está fresh ("Token not ready for refresh")
```

## Pendiente

- Shape exacto de `/v0/transactions/execute` · capturar de Network tab Trueno con dispersión real
- TOTP secret storage opcional · permitir auto-generar PINs sin operador (necesita pyotp + secret)
- Persistir log a archivo · audit trail off-process
- Backup config local · evitar re-pegar Kashport token cada arranque
