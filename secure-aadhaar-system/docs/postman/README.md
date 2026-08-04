# Testing the backend in Postman

Two files in this folder let you exercise the whole backend without building
any requests by hand:

- `secure-aadhaar-system.postman_collection.json`
- `secure-aadhaar-system.postman_environment.json`

For the full request/response reference (every field, every error code),
see `../POSTMAN_TESTING_GUIDE.md`. This file is just the steps to get the
collection running.

## Steps

1. **Import both files.** In Postman: **File → Import**, then drag in both
   the collection and the environment JSON.
2. **Select the environment.** Pick **"Secure Aadhaar System (local)"** from
   the environment dropdown in the top-right corner of the Postman window.
3. **Set two environment variables for your machine:**
   - `base_url` — defaults to `http://localhost:8000` (uvicorn's default
     when you run `uvicorn app.main:app --reload` with no `--port`). Check
     `frontend/.env`'s `VITE_API_BASE_URL` if your local backend runs on a
     different port.
   - `setup_token` — copy the value of `ADMIN_SETUP_TOKEN` from
     `backend/.env`.
4. **Run requests top to bottom, folder by folder:**
   - **Health** — a quick liveness check.
   - **Flow A** — user signup, login, submit an Aadhaar number, view own
     submissions, logout.
   - **Flow B** — first-ever admin (master) self-registration, gated by
     `setup_token`.
   - **Flow C** — admin login, list all submissions, decrypt one, logout.
   - **Flow D** — master creates a sub-admin; sub-admin logs in and
     decrypts a record that existed before they did.
   - **Flow E** — date-range audit report (JSON and PDF export), and the
     full audit log (every login/logout/submit/decrypt event with a real
     timestamp).
5. **Fill in `totp_code` manually, right before sending.** Every request
   that needs a TOTP code (`admin/register/confirm`, `admin/login`,
   `admin/admins/confirm`) reads it from the `totp_code` environment
   variable. It's a live 6-digit code from an authenticator app and rotates
   every 30 seconds, so paste it in and hit Send immediately — don't
   prepare the request in advance.

Everything else is automatic:

- **Cookies.** Auth is httpOnly session cookies (`user_session`,
  `admin_session`), not bearer tokens. Postman's desktop app stores and
  resends them automatically, just like a browser — nothing to copy into
  headers.
- **Chained variables.** Each request's *Tests* script captures what the
  next one needs into the environment automatically: `reference_id`
  (from Flow A's submit), `registration_token` / `manual_secret` (from
  Flow B/D's start step), `sub_admin_id` (from Flow D's confirm step).
- **Fresh timestamps.** The submit request's `ts` field uses Postman's
  built-in `{{$isoTimestamp}}` dynamic variable, so it's always within the
  server's 5-minute freshness window without you touching it.

## If something fails partway through

- **401 on Flow B**: `setup_token` doesn't match `ADMIN_SETUP_TOKEN`, or an
  admin already exists on this deployment (Flow B only ever works once).
- **401 on Flow C/D admin requests**: the admin session idles out after 5
  minutes — re-run the login step.
- **503 on Flow A's submit step**: no admin has been registered yet — run
  Flow B first.
- **400 with `bad_signature` or `crypto_error` on decrypt**: the record was
  tampered with, or the logged-in admin has no wrapped key for that
  specific record (e.g. a sub-admin created *without* running Flow D's
  retroactive re-wrap).
