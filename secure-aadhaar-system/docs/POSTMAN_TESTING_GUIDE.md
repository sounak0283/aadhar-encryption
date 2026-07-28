# Postman Testing Guide — Secure Aadhaar Transmission System

This walks through every API flow end-to-end with exact request/response
bodies, so you can build a Postman collection and exercise the whole system.

## Before you start

**Auth model: httpOnly session cookies, not bearer tokens.** There is no
token to copy out of a response and paste into an `Authorization` header.
When you log in, the server sends back a `Set-Cookie` header
(`user_session` or `admin_session`); Postman's desktop app stores and
resends it automatically for later requests to the same host — just like a
browser. Two independent cookies exist side by side, so you can be logged
in as a regular user *and* an admin at the same time in one Postman session
without either one clobbering the other.

**Base URL**: create a Postman environment with a variable
`base_url = http://localhost:8003` (check `frontend/.env`'s
`VITE_API_BASE_URL` if this project's backend port has changed) and use
`{{base_url}}/api/...` in every request, so you only ever update it in one
place.

**Headers**: every `POST` with a JSON body needs `Content-Type: application/json`
— set this in Postman's Body tab by choosing **raw → JSON**, which adds the
header automatically.

**TOTP codes**: admin endpoints need a live 6-digit code from an
authenticator app. It rotates every 30 seconds, so type it in and send
immediately — don't prepare the request in advance and send it later.

**A valid Aadhaar number for testing**: random 12 digits will fail with
`400` — the number's last digit must satisfy a real Verhoeff checksum.
Use one of these:
```
102938475615
564738291043
999888777669
```

---

## Flow A — Regular user: sign up, log in, submit, view own submissions

### A1. Sign up
```
POST {{base_url}}/api/auth/signup
Content-Type: application/json

{
  "username": "alice",
  "password": "a-strong-password"
}
```
Response `200`:
```json
{ "status": "ok" }
```
Errors: `409` if the username is taken, `422` if username < 3 chars or password < 8 chars.

### A2. Log in
```
POST {{base_url}}/api/auth/login
Content-Type: application/json

{
  "username": "alice",
  "password": "a-strong-password"
}
```
Response `200`, plus a `Set-Cookie: user_session=...` header — this is the
"bearer token" equivalent, handled automatically by Postman from here on.
Errors: `401` for wrong username or password (deliberately the same error
either way, so you can't probe which usernames exist).

### A3. Confirm you're logged in
```
GET {{base_url}}/api/auth/me
```
Response `200`:
```json
{ "id": "6a...", "username": "alice" }
```
`401` if the cookie didn't get sent — check Postman's **Cookies** link
below the Send button if this happens unexpectedly.

### A4. Submit an Aadhaar number
```
POST {{base_url}}/api/aadhaar
Content-Type: application/json

{ "aadhaar_number": "102938475615" }
```
Response `200`:
```json
{ "reference_id": "6a6..." }
```
Save `reference_id` — you'll need it in Flow C. Errors: `401` if not
logged in, `400` if the number fails validation, `503` if no admin has
been registered on this deployment yet (nothing exists to wrap the
encryption key to).

### A5. View your own submission history
```
GET {{base_url}}/api/my-submissions
```
Response `200`:
```json
[
  { "id": "6a6...", "created_at": "2026-07-22T11:13:36.938000Z", "masked_preview": "XXXX-XXXX-5615" }
]
```
Only ever shows *this* user's own submissions — no plaintext, no decrypt
capability, that's admin-only (Flow C).

### A6. Log out
```
POST {{base_url}}/api/auth/logout
```
Response `200`. Afterward, A3–A5 should all return `401` again.

---

## Flow B — First-ever admin (master) self-registration

Only works once, ever, per deployment — refuses with `409` if any admin
already exists. Needs `ADMIN_SETUP_TOKEN` from the server's `.env`.

### B1. Check registration status
```
GET {{base_url}}/api/admin/register/status
```
Response `200`: `{ "registered": false }` (or `true` if a master already exists).

### B2. Start registration
```
POST {{base_url}}/api/admin/register/start
Content-Type: application/json

{
  "setup_token": "<ADMIN_SETUP_TOKEN from .env>",
  "username": "admin",
  "password": "at-least-12-characters"
}
```
Response `200`:
```json
{
  "registration_token": "abc123...",
  "otpauth_uri": "otpauth://totp/Secure%20Aadhaar%20System:admin?secret=...&issuer=...",
  "manual_secret": "JBSWY3DPEHPK3PXP",
  "qr_code_png_base64": "iVBORw0KGgoAAAANSUhEUgA..."
}
```
Save `registration_token`. To actually get a scannable QR, paste the
`qr_code_png_base64` value into a browser address bar as
`data:image/png;base64,<value>`, or just enter `manual_secret` into your
authenticator app's "enter code manually" option.
Errors: `403` wrong setup token, `409` already registered, `503` if
`ADMIN_SETUP_TOKEN` isn't configured server-side, `422` weak
username/password.

### B3. Confirm registration
```
POST {{base_url}}/api/admin/register/confirm
Content-Type: application/json

{
  "registration_token": "<from B2>",
  "totp_code": "123456"
}
```
Response `200`: `{ "status": "ok" }`. Errors: `401` wrong code, `404`
expired/unknown token (registrations expire after 10 minutes), `409` if
someone else registered first in the meantime.

---

## Flow C — Admin login, view all submissions, decrypt one

### C1. Log in
```
POST {{base_url}}/api/admin/login
Content-Type: application/json

{
  "username": "admin",
  "password": "at-least-12-characters",
  "totp_code": "123456"
}
```
Response `200`, sets `admin_session` cookie. `401` for any wrong field
(password, username, or code — same generic error for all three).

### C2. Confirm identity
```
GET {{base_url}}/api/admin/me
```
Response `200`:
```json
{ "id": "6a...", "username": "admin", "role": "master" }
```
`role` is `"master"` or `"sub"` — matters for Flow D.

### C3. List all submissions (masked)
```
GET {{base_url}}/api/admin/submissions
```
Response `200`:
```json
[
  { "id": "6a6...", "created_at": "2026-07-22T11:13:36.938000Z", "masked_preview": "XXXX-XXXX-5615" }
]
```
Every admin sees every submission here (unlike `/api/my-submissions`,
which is scoped to one regular user) — nothing decrypted yet.

### C4. Decrypt one record
```
POST {{base_url}}/api/admin/submissions/{{reference_id}}/decrypt
```
(use the `reference_id` from A4, or any `id` from C3)

Response `200`:
```json
{ "aadhaar_number": "102938475615" }
```
This is the one and only moment the real number appears anywhere. Response
also carries `Cache-Control: no-store`. Errors: `404` unknown id, `400`
with `detail: "bad_signature"` or `"crypto_error"` if the record was
tampered with or you're not authorized for that particular record, `401`
if not logged in.

### C5. Log out
```
POST {{base_url}}/api/admin/logout
```

---

## Flow D — Master creates a sub-admin; sub-admin logs in and decrypts

This is the interesting one: a sub-admin created *after* records already
exist can still decrypt those pre-existing records — the master's
"confirm" step retroactively re-wraps every existing container for them.

**Prerequisite**: be logged in as **master** (Flow C1, `role: "master"` —
these three endpoints return `403` for a `"sub"` admin).

### D1. Start sub-admin creation
```
POST {{base_url}}/api/admin/admins/start
Content-Type: application/json

{
  "username": "sub1",
  "password": "at-least-12-characters"
}
```
Response `200` — identical shape to B2 (`registration_token`,
`otpauth_uri`, `manual_secret`, `qr_code_png_base64`). This is the new
sub-admin's own QR code, hand it to them (or scan it yourself for testing).
Errors: `409` username taken, `403` if you're not master.

### D2. Confirm sub-admin creation
```
POST {{base_url}}/api/admin/admins/confirm
Content-Type: application/json

{
  "registration_token": "<from D1>",
  "totp_code": "123456"
}
```
Response `200`:
```json
{ "admin_id": "6a6...", "containers_granted": 3 }
```
`containers_granted` is how many pre-existing records this new sub-admin
was just given access to — the retroactive re-wrap, proven right here in
the response.

### D3. List all admins (master only)
```
GET {{base_url}}/api/admin/admins
```
Response `200`:
```json
[
  { "id": "6a...", "username": "admin", "role": "master", "status": "active", "created_at": "...", "created_by": null },
  { "id": "6a...", "username": "sub1", "role": "sub", "status": "active", "created_at": "...", "created_by": "6a..." }
]
```

### D4. Log out of master, log in as the sub-admin
```
POST {{base_url}}/api/admin/logout
```
then
```
POST {{base_url}}/api/admin/login
Content-Type: application/json

{
  "username": "sub1",
  "password": "at-least-12-characters",
  "totp_code": "123456"
}
```

### D5. Sub-admin decrypts a record submitted *before they existed*
```
POST {{base_url}}/api/admin/submissions/{{reference_id}}/decrypt
```
Should return `200` with the real number — same as C4, proving retroactive
access actually works, not just that `containers_granted` said it would.

---

## Chaining requests automatically (optional but worth doing)

Rather than copy-pasting `registration_token` / `reference_id` /
`admin_id` between requests by hand, add a **Tests** tab script to the
response that produces them, so Postman stores it as an environment
variable automatically:

```javascript
// On the /api/admin/register/start (or /api/admin/admins/start) request's Tests tab:
const body = pm.response.json();
pm.environment.set("registration_token", body.registration_token);
pm.environment.set("manual_secret", body.manual_secret);

// On the /api/aadhaar request's Tests tab:
pm.environment.set("reference_id", pm.response.json().reference_id);

// On the /api/admin/admins/confirm request's Tests tab:
pm.environment.set("sub_admin_id", pm.response.json().admin_id);
```
Then use `{{registration_token}}`, `{{reference_id}}`, etc. directly in
later requests' URLs/bodies.

---

## Full endpoint reference

| Method | Path | Auth | Flow |
|---|---|---|---|
| POST | `/api/auth/signup` | none | A1 |
| POST | `/api/auth/login` | none | A2 |
| GET | `/api/auth/me` | user session | A3 |
| POST | `/api/aadhaar` | user session | A4 |
| GET | `/api/my-submissions` | user session | A5 |
| POST | `/api/auth/logout` | user session | A6 |
| GET | `/api/admin/register/status` | none | B1 |
| POST | `/api/admin/register/start` | `ADMIN_SETUP_TOKEN` | B2 |
| POST | `/api/admin/register/confirm` | none (registration token) | B3 |
| POST | `/api/admin/login` | none | C1 |
| GET | `/api/admin/me` | admin session | C2 |
| GET | `/api/admin/submissions` | admin session | C3 |
| POST | `/api/admin/submissions/{id}/decrypt` | admin session | C4 |
| POST | `/api/admin/logout` | admin session | C5 |
| POST | `/api/admin/admins/start` | admin session, master only | D1 |
| POST | `/api/admin/admins/confirm` | admin session, master only | D2 |
| GET | `/api/admin/admins` | admin session, master only | D3 |
| GET | `/health` | none | — |

## Status codes you'll see

| Code | Meaning here |
|---|---|
| 200 | Success |
| 400 | Bad input (invalid Aadhaar number) or crypto rejection (`bad_signature` / `crypto_error` on decrypt) |
| 401 | Not authenticated, or wrong credentials |
| 403 | Authenticated but not authorized (e.g. a sub-admin hitting a master-only endpoint) |
| 404 | Unknown record/registration token |
| 409 | Conflict (username taken, admin already registered) |
| 422 | Request body failed schema validation (e.g. password too short) — from Pydantic, before your handler code even runs |
| 503 | Server not ready for this request (no admin registered yet, or `ADMIN_SETUP_TOKEN` not configured) |
