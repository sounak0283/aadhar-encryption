# Secure Aadhaar Transmission System — API Reference

FastAPI backend (`backend/app`). Generated from source: `app/main.py`, `app/routers/*`, `app/models/*`, `app/deps.py`.

Interactive schema is also served by FastAPI itself at `/docs` (Swagger) and `/openapi.json`.

---

## 1. Conventions

| | |
|---|---|
| **Base URL** | `http://localhost:8000` (uvicorn default) |
| **Content type** | `application/json` for all request/response bodies except the PDF export |
| **App title** | `Secure Aadhaar Transmission System` |

### CORS

Configured in `app/main.py`:

- `allow_origins`: exactly one origin — `FRONTEND_ORIGIN` env var, default `http://localhost:5173`
- `allow_credentials`: `true` (required — auth is cookie based)
- `allow_methods`: `GET`, `POST` only
- `allow_headers`: `*`

### Authentication

Two independent, cookie-based session systems. Sessions are held **in process memory**, so a server restart invalidates every session.

| Cookie | Who | TTL | Set by | Required by |
|---|---|---|---|---|
| `user_session` | Regular submitter | 30 min | `POST /api/auth/login` | `/api/aadhaar`, `/api/my-submissions`, `/api/auth/me` |
| `admin_session` | Admin (master or sub) | 5 min | `POST /api/admin/login` | all `/api/admin/*` except register/login endpoints |

Both cookies are set `HttpOnly`, `Secure`, `SameSite=Strict`. Because `Secure` is set, browsers will not store them over plain HTTP on a non-`localhost` host.

The admin session additionally holds the **unlocked private identity** in memory — that is why its TTL is only 5 minutes; decryption is impossible without it.

**Roles.** An admin is `master` or `sub`. Endpoints marked *master only* return `403 master admin only` for a `sub` admin.

### Rate limiting

`slowapi`, keyed by client IP (`get_remote_address`). Exceeding a limit returns **429**. Limits are noted per endpoint below. Note that `POST /api/admin/login` has **no** rate limit.

### Error shape

Standard FastAPI errors:

```json
{ "detail": "invalid credentials" }
```

Pydantic validation failures return **422** with the usual `detail` array of field errors.

---

## 2. Health

### `GET /health`

No auth. Liveness probe.

```json
{ "status": "ok" }
```

---

## 3. User authentication — `/api/auth`

Regular users: the people who submit Aadhaar numbers.

### `POST /api/auth/signup`

Rate limit **10/minute**. No auth.

```json
{ "username": "alice", "password": "hunter2hunter2" }
```

| Field | Rule |
|---|---|
| `username` | string, min length 3 |
| `password` | string, min length 8 |

**200** → `{ "status": "ok" }`
**409** → `username already in use`
**422** → field validation failure

### `POST /api/auth/login`

Rate limit **10/minute**. No auth.

```json
{ "username": "alice", "password": "hunter2hunter2" }
```

**200** → `{ "status": "ok" }` plus `Set-Cookie: user_session=…; HttpOnly; Secure; SameSite=Strict; Max-Age=1800`
**401** → `invalid credentials` — returned identically for an unknown username, a non-`active` account, and a wrong password (no user enumeration).

### `GET /api/auth/me`

Requires `user_session`.

```json
{ "id": "665f…", "username": "alice" }
```

**401** → `not authenticated` (no cookie) or `session expired or invalid`

### `POST /api/auth/logout`

No auth required; destroys the session named by the cookie if one is present, and clears the cookie either way.

**200** → `{ "status": "ok" }`

---

## 4. Submissions (user-facing)

### `POST /api/aadhaar`

Requires `user_session`. Rate limit **5/minute**.

Encrypts the Aadhaar number under a fresh DEK, wraps that DEK separately for **every currently active admin**, signs the container, and stores it.

```json
{
  "aadhaar_number": "234567890124",
  "consent": true,
  "ts": "2026-08-03T10:15:30Z"
}
```

| Field | Rule |
|---|---|
| `aadhaar_number` | exactly 12 digits, `^\d{12}$`, **and** a valid Verhoeff check digit (UIDAI's checksum scheme) |
| `consent` | required, must be literally `true` — explicit informed consent, analogous to UIDAI's `rc="Y"` |
| `ts` | required, **timezone-aware** ISO-8601 capture timestamp; must be within ±300 s of server time |

**200**

```json
{ "reference_id": "a1b2c3…", "masked_preview": "XXXX-XXXX-0124" }
```

`reference_id` is derived deterministically from an HMAC lookup tag of the number. Submitting the **same Aadhaar number twice returns the same `reference_id`** and does not store a second copy — a stable per-deployment identifier, mirroring UIDAI's UID Token.

**400** — `detail` is one of:
- `invalid Aadhaar number` (12 digits but the Verhoeff checksum fails)
- `request_expired` (`ts` older than 300 s)
- `timestamp_in_future` (`ts` more than 300 s ahead)

**401** — no/expired `user_session`
**422** — `consent` not `true`, `ts` naive, or format violations
**503** — `no admin is registered yet — submissions are not accepted`

### `GET /api/my-submissions`

Requires `user_session`. Returns only the calling user's submissions, newest first.

```json
[
  { "id": "a1b2c3…", "created_at": "2026-08-03T10:15:31Z", "masked_preview": "XXXX-XXXX-0124" }
]
```

Never returns plaintext Aadhaar numbers.

---

## 5. Admin registration — `/api/admin/register`

Two-step flow that bootstraps the **first (master) admin only**, gated by the `ADMIN_SETUP_TOKEN` server secret. Pending registrations expire after **10 minutes**.

### `GET /api/admin/register/status`

No auth. Lets the UI decide whether to show the setup screen.

```json
{ "registered": true }
```

### `POST /api/admin/register/start`

Rate limit **5/minute**. No session; authorized by `setup_token`.

```json
{ "setup_token": "…", "username": "root-admin", "password": "correct horse battery staple" }
```

| Field | Rule |
|---|---|
| `setup_token` | must equal `ADMIN_SETUP_TOKEN` (constant-time compare) |
| `username` | min length 3 |
| `password` | min length 12 |

**200**

```json
{
  "registration_token": "…",
  "otpauth_uri": "otpauth://totp/…",
  "manual_secret": "JBSWY3DPEHPK3PXP",
  "qr_code_png_base64": "iVBORw0KGgo…"
}
```

**400** — password too short / username too short (message from the service)
**403** — `invalid setup token`
**409** — `an admin already exists`
**503** — `admin registration is not configured on this server` (`ADMIN_SETUP_TOKEN` unset)

### `POST /api/admin/register/confirm`

Rate limit **10/minute**. Proves the operator actually enrolled the TOTP secret before the admin is persisted.

```json
{ "registration_token": "…", "totp_code": "492013" }
```

`totp_code` must match `^\d{6}$`.

**200** → `{ "status": "ok" }`
**401** → `invalid authenticator code`
**404** → `unknown or expired registration`
**409** → `an admin already exists`

---

## 6. Admin session — `/api/admin`

### `POST /api/admin/login`

No rate limit. Three factors: password, TOTP, and a successful password-derived unlock of the stored identity.

```json
{ "username": "root-admin", "password": "…", "totp_code": "492013" }
```

**200** → `{ "status": "ok" }` plus `Set-Cookie: admin_session=…; HttpOnly; Secure; SameSite=Strict; Max-Age=300`
**401** → `invalid credentials` — same message for unknown username, disabled account, bad TOTP, and failed identity unlock.

### `GET /api/admin/me`

Requires `admin_session`.

```json
{ "id": "665f…", "username": "root-admin", "role": "master" }
```

### `POST /api/admin/logout`

No auth required. Destroys the session (and with it the in-memory unlocked identity) and clears the cookie.

**200** → `{ "status": "ok" }`

---

## 7. Sub-admin management — master only

### `GET /api/admin/admins`

Requires `admin_session` with role `master`.

```json
[
  {
    "id": "665f…",
    "username": "root-admin",
    "role": "master",
    "status": "active",
    "created_at": "2026-07-01T09:00:00Z",
    "created_by": null
  }
]
```

`role` ∈ `master | sub`; `status` ∈ `active | disabled`; `created_by` is the creating admin's id, `null` for the master.

**403** → `master admin only`

### `POST /api/admin/admins/start`

Master only. Rate limit **10/minute**. Pending registration TTL **10 minutes**.

```json
{ "username": "auditor-2", "password": "correct horse battery staple" }
```

Same field rules as `register/start` (username ≥ 3, password ≥ 12). Response body is identical to `RegisterStartResponse` — hand `qr_code_png_base64` / `manual_secret` to the new admin for enrollment.

**400** — weak password / invalid username
**409** — `username already in use`
**403** — not a master

### `POST /api/admin/admins/confirm`

Master only. Rate limit **15/minute**. The master's own unlocked identity is used to re-wrap every existing container's DEK for the new admin, which is what `containers_granted` counts.

```json
{ "registration_token": "…", "totp_code": "492013" }
```

**200**

```json
{ "admin_id": "6660…", "containers_granted": 42 }
```

**401** → `invalid authenticator code`
**404** → `unknown or expired registration`

---

## 8. Admin submissions & audit

### `GET /api/admin/submissions`

Any authenticated admin. All submissions in the system, newest first. Masked previews only.

```json
[
  { "id": "a1b2c3…", "created_at": "2026-08-03T10:15:31Z", "masked_preview": "XXXX-XXXX-0124" }
]
```

### `POST /api/admin/submissions/{submission_id}/decrypt`

Any authenticated admin, but only succeeds if that admin has a `wrapped_deks` entry for the record. `submission_id` is the `reference_id`.

Every attempt — success or failure — is written to the audit log with the outcome and the admin's username. The response carries `Cache-Control: no-store`.

**200**

```json
{ "aadhaar_number": "234567890124" }
```

**400** — `bad_signature` (container signature failed verification) or `crypto_error` (unwrap/decrypt failed, e.g. this admin has no key for the record)
**404** — `not found`
**401** — no/expired `admin_session`

### `GET /api/admin/audit-report`

Any authenticated admin. **One row per hit**, not per record — every submit and every decrypt attempt against an Aadhaar record produces its own row with its own timestamp, so a record submitted once and later decrypted three times shows up as four rows, not one static row frozen at the original submission time.

| Query param | Type | Notes |
|---|---|---|
| `from_date` | `YYYY-MM-DD` | required, inclusive |
| `to_date` | `YYYY-MM-DD` | required, inclusive |

```json
[
  {
    "date": "2026-08-03",
    "reference_id": "a1b2c3…",
    "masked_aadhaar_no": "XXXX-XXXX-0124",
    "request_datetime": "2026-08-03T10:15:31Z"
  },
  {
    "date": "2026-08-03",
    "reference_id": "a1b2c3…",
    "masked_aadhaar_no": "XXXX-XXXX-0124",
    "request_datetime": "2026-08-03T14:02:09Z"
  },
  { "date": "2026-08-04", "reference_id": null, "masked_aadhaar_no": null, "request_datetime": null }
]
```

The two rows above are the *same record* (same `reference_id`) — one row for its submission, one for a later decrypt, each with its own `request_datetime`. `date` is present for **every** day in the range; days with zero hits come back as a single row with all other fields `null`. Login/logout events aren't record-scoped and never appear here — see `GET /api/admin/audit-log` below for those.

**400** — `from_date must not be after to_date`
**422** — unparseable date

### `GET /api/admin/audit-report/pdf`

Same auth and `from_date` / `to_date` query params, plus an optional column selector. Returns the rendered report.

| Query param | Type | Notes |
|---|---|---|
| `columns` | comma-separated | optional; subset of `date`, `reference_id`, `masked_aadhaar_no`, `request_datetime`. Defaults to all four. |

- `Content-Type: application/pdf`
- `Content-Disposition: attachment; filename="audit-report_<from>_<to>.pdf"`

**400** — `from_date must not be after to_date`, or an unknown/empty `columns` value

### `GET /api/admin/audit-log`

Any authenticated admin. Every recorded security event with a real per-hit timestamp — admin login/logout, user login/logout, Aadhaar submission attempts, and decrypt attempts — newest first.

| Query param | Type | Notes |
|---|---|---|
| `from_date` | `YYYY-MM-DD` | required, inclusive |
| `to_date` | `YYYY-MM-DD` | required, inclusive |

```json
[
  { "ts": "2026-08-03T10:21:47Z", "action": "decrypt",     "result": "success",             "username": "root-admin", "container_id": "a1b2c3…" },
  { "ts": "2026-08-03T10:20:03Z", "action": "admin_login", "result": "success",             "username": "root-admin", "container_id": null },
  { "ts": "2026-08-03T10:15:31Z", "action": "submit",      "result": "success",             "username": "alice",      "container_id": "a1b2c3…" },
  { "ts": "2026-08-03T10:14:51Z", "action": "user_login",  "result": "success",             "username": "alice",      "container_id": null },
  { "ts": "2026-08-03T09:58:12Z", "action": "admin_login", "result": "invalid_credentials", "username": "root-admin", "container_id": null }
]
```

`action` ∈ `admin_login | admin_logout | user_login | user_logout | submit | decrypt`. `result` is `success` for logouts, and for the rest is either `success` or a short failure reason (`invalid_credentials`, `invalid_aadhaar_number`, `request_expired`, `timestamp_in_future`, `no_active_admins`, `bad_signature`, `crypto_error`). `container_id` is only populated for `submit` and `decrypt` events.

**400** — `from_date must not be after to_date`

---

## 9. Endpoint summary

| Method | Path | Auth | Rate limit |
|---|---|---|---|
| GET | `/health` | — | — |
| POST | `/api/auth/signup` | — | 10/min |
| POST | `/api/auth/login` | — | 10/min |
| GET | `/api/auth/me` | user | — |
| POST | `/api/auth/logout` | — | — |
| POST | `/api/aadhaar` | user | 5/min |
| GET | `/api/my-submissions` | user | — |
| GET | `/api/admin/register/status` | — | — |
| POST | `/api/admin/register/start` | setup token | 5/min |
| POST | `/api/admin/register/confirm` | reg. token | 10/min |
| POST | `/api/admin/login` | — | — |
| GET | `/api/admin/me` | admin | — |
| POST | `/api/admin/logout` | — | — |
| GET | `/api/admin/admins` | master | — |
| POST | `/api/admin/admins/start` | master | 10/min |
| POST | `/api/admin/admins/confirm` | master | 15/min |
| GET | `/api/admin/submissions` | admin | — |
| POST | `/api/admin/submissions/{id}/decrypt` | admin | — |
| GET | `/api/admin/audit-report` | admin | — |
| GET | `/api/admin/audit-report/pdf` | admin | — |
| GET | `/api/admin/audit-log` | admin | — |

---

## 10. Server configuration

Read via `app/config.py` from the environment / `.env`:

| Variable | Required | Default | Purpose |
|---|---|---|---|
| `APP_TOTP_KEY` | yes | — | 32-byte base64 key encrypting admins' TOTP secrets at rest |
| `TOKEN_HMAC_KEY` | yes | — | 32-byte base64 key for the deterministic per-number lookup tag |
| `ADMIN_SETUP_TOKEN` | for web registration | — | Shared secret gating `POST /api/admin/register/start` |
| `MONGO_URI` | no | `mongodb://localhost:27017` | Database |
| `MONGO_DB_NAME` | no | `secure_aadhaar` | Database name |
| `FRONTEND_ORIGIN` | no | `http://localhost:5173` | The single allowed CORS origin |
| `ADMIN_KEY_PROVIDER` | no | `local` | Bootstrap-time only: `local` or `aws-kms` |
| `AWS_KMS_KEY_ID` | no | — | Bootstrap-time only, when provider is `aws-kms` |

A missing `APP_TOTP_KEY` / `TOKEN_HMAC_KEY` raises at request time, not startup.
