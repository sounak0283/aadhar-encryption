# Secure Aadhaar Transmission System
## API Test Guide (Postman)

---

### Document Control

| Field | Value |
|---|---|
| Document Title | Secure Aadhaar Transmission System — API Test Guide |
| Document Type | API Test Plan / Test Case Specification |
| Tooling | Postman (Desktop or Web) |
| Applies To | Backend REST API (`/health`, `/api/auth/*`, `/api/aadhaar`, `/api/my-submissions`, `/api/admin/*`) |
| Version | 1.0 |
| Date | 2026-08-04 |
| Classification | Internal Use |
| Status | Approved for Testing |

---

## Table of Contents

1. Introduction
2. System Overview
3. Postman Environment Setup
4. Global Testing Conventions
5. Test Suite
   - 5.0 Module 0 — Health Check
   - 5.1 Module A — User Authentication & Submission
   - 5.2 Module B — Admin Registration (First Admin)
   - 5.3 Module C — Admin Session, Submissions & Decryption
   - 5.4 Module D — Sub-Admin Management
   - 5.5 Module E — Audit Reporting & Logging
6. Test Data Reference
7. Appendix A — Full Endpoint Reference
8. Appendix B — Environment Variable Reference
9. Appendix C — Test Execution Log Template
10. Revision History

---

## 1. Introduction

### 1.1 Purpose

This document specifies the complete set of API test cases for the Secure Aadhaar Transmission System backend. It is intended to be executed manually (or semi-automated) in Postman by a QA engineer, developer, or auditor who needs to verify that every endpoint behaves as specified — both on the success path and under invalid/unauthorized conditions.

### 1.2 Audience

QA engineers, backend developers, and security reviewers responsible for verifying the API prior to a release or as part of a periodic regression pass.

### 1.3 Scope

This guide covers all 21 HTTP endpoints exposed by the backend, grouped into six functional modules. Each endpoint's test case specifies: the request (method, headers, body, query parameters), the expected success response, and the expected error responses for the most important negative scenarios.

Out of scope: frontend UI testing, load/performance testing, and infrastructure/deployment testing.

---

## 2. System Overview

The backend is a FastAPI application implementing envelope-encrypted storage and controlled decryption of Aadhaar numbers, with two independent authentication realms:

| Realm | Who | Session Cookie | Session Lifetime |
|---|---|---|---|
| Regular user | People submitting Aadhaar numbers | `user_session` | 30 minutes, sliding |
| Admin | People authorized to decrypt and audit | `admin_session` | 5 minutes, sliding |

Authentication is **cookie-based**, not token-based. There is no bearer token to copy into an `Authorization` header — logging in sets an `HttpOnly` cookie, and Postman's desktop application stores and resends it automatically on subsequent requests, exactly like a browser.

**Base URL** (default): `http://localhost:8000` — or whichever port your local instance runs on (check `frontend/.env`'s `VITE_API_BASE_URL` if unsure).

---

## 3. Postman Environment Setup

Before executing any test case, create a dedicated Postman environment so `base_url` and other shared values are never hardcoded into individual requests.

### 3.1 Steps to create the environment

1. Open Postman.
2. In the left sidebar, click **Environments**.
3. Click the **+** (plus) icon to create a new environment.
4. Rename it to **`Secure Aadhaar System — Test`**.
5. Add each variable listed in the table below (Section 3.2) — for each row, click **Add a new variable**, enter the **Variable** name, and set an **Initial Value** (this is copied to **Current Value** automatically).
6. Click **Save**.
7. In the top-right corner of the Postman window, open the environment dropdown and select **Secure Aadhaar System — Test** so it becomes active for all requests.

### 3.2 Environment variables to create

| Variable | Initial Value | Type | Set By | Description |
|---|---|---|---|---|
| `base_url` | `http://localhost:8000` | default | You (manual) | Root URL of the running backend |
| `setup_token` | *(copy from `backend/.env` → `ADMIN_SETUP_TOKEN`)* | secret | You (manual) | Shared secret required to self-register the first (master) admin |
| `totp_code` | *(blank)* | default | You (manual, per request) | Live 6-digit authenticator code — rotates every 30 seconds |
| `user_username` | `alice` | default | You (manual) | Regular test user's username |
| `user_password` | `a-strong-password-1` | default | You (manual) | Regular test user's password |
| `admin_username` | `admin` | default | You (manual) | Master admin's username |
| `admin_password` | `at-least-12-characters` | default | You (manual) | Master admin's password |
| `sub_admin_username` | `sub1` | default | You (manual) | Sub-admin's username, used in Module D |
| `sub_admin_password` | `at-least-12-characters-2` | default | You (manual) | Sub-admin's password |
| `registration_token` | *(blank)* | default | Captured automatically | Set by the Tests script on the "start" registration requests |
| `manual_secret` | *(blank)* | default | Captured automatically | TOTP secret returned by the "start" registration requests |
| `reference_id` | *(blank)* | default | Captured automatically | Set by the Tests script on the submit-Aadhaar request |
| `sub_admin_id` | *(blank)* | default | Captured automatically | Set by the Tests script on the sub-admin confirm request |
| `from_date` | `2026-08-01` | default | You (manual) | Start of the date range used in Module E |
| `to_date` | `2026-08-31` | default | You (manual) | End of the date range used in Module E |

> **Note on "Captured automatically":** several test cases below include a *Postman Test Script* snippet. Pasting that snippet into the request's **Tests** tab makes Postman populate the corresponding environment variable from the response automatically, so you never have to copy-paste IDs/tokens between requests by hand.

### 3.3 Verifying the setup

Run the **Health Check** request (Section 5.0) immediately after activating the environment. A `200 OK` with `{"status": "ok"}` confirms `base_url` is correct and the backend is reachable before you proceed to any other test case.

---

## 4. Global Testing Conventions

### 4.1 Headers

Every request with a JSON body requires:
```
Content-Type: application/json
```
In Postman, selecting **Body → raw → JSON** adds this header automatically.

### 4.2 Cookies

Do not add `Cookie` headers manually. Postman's cookie jar handles `user_session` and `admin_session` automatically once a login request succeeds. Both cookies can be active at the same time (different names), so you can be logged in as a regular user and an admin simultaneously within the same Postman session.

### 4.3 TOTP (Time-based One-Time Password) codes

Three endpoints require a live 6-digit TOTP code: `POST /api/admin/register/confirm`, `POST /api/admin/login`, and `POST /api/admin/admins/confirm`. This code rotates every 30 seconds. **Type the code into the `totp_code` environment variable and send the request immediately** — do not prepare a request in advance and send it later, or the code will have expired.

### 4.4 Standard HTTP status codes used by this API

| Code | Meaning in this system |
|---|---|
| 200 | Success |
| 400 | Bad input — invalid Aadhaar number/date range, or a crypto rejection (`bad_signature` / `crypto_error`) |
| 401 | Not authenticated, wrong credentials, or expired session |
| 403 | Authenticated but not authorized (e.g. a sub-admin calling a master-only endpoint) |
| 404 | Unknown record or expired/unknown registration token |
| 409 | Conflict — username already taken, or an admin already exists |
| 422 | Request body failed schema validation (Pydantic), before handler code runs |
| 429 | Rate limit exceeded |
| 503 | Server not ready for this request (no admin registered yet, or a required secret is unconfigured) |

### 4.5 Rate limits

Rate limits are enforced per client IP address. Exceeding one returns `429 Too Many Requests`. Limits are noted in each test case's summary table where applicable; endpoints with no limit listed have none.

### 4.6 Test Aadhaar numbers

The Aadhaar number field requires a syntactically valid 12-digit number whose final digit satisfies a Verhoeff checksum (the same check-digit scheme UIDAI uses). Random 12-digit numbers will fail with `400`. Use one of the following pre-validated numbers for testing:

```
102938475615
564738291043
999888777669
```

---

## 5. Test Suite

---

### 5.0 Module 0 — Health Check

#### TC-00 — Service Liveness Check

| Field | Detail |
|---|---|
| Endpoint | `GET {{base_url}}/health` |
| Purpose | Confirms the backend process is running and reachable |
| Authentication | None |
| Rate Limit | None |

**Request Body:** none

**Expected Result — Success**
- Status Code: `200 OK`
- Response Body:
```json
{ "status": "ok" }
```

**Postman Test Script**
```javascript
pm.test("Status is 200", () => pm.response.to.have.status(200));
pm.test("Body reports ok", () => pm.expect(pm.response.json().status).to.eql("ok"));
```

---

### 5.1 Module A — User Authentication & Submission

Covers the lifecycle of a regular (non-admin) user: sign up, log in, submit an Aadhaar number, view their own submissions, and log out.

#### TC-A1 — User Sign Up

| Field | Detail |
|---|---|
| Endpoint | `POST {{base_url}}/api/auth/signup` |
| Purpose | Register a new regular user account |
| Authentication | None |
| Rate Limit | 10 requests / minute per IP |

**Request Headers**
```
Content-Type: application/json
```

**Request Body**
```json
{
  "username": "{{user_username}}",
  "password": "{{user_password}}"
}
```

**Field Validation Rules**

| Field | Type | Rule |
|---|---|---|
| `username` | string | minimum 3 characters |
| `password` | string | minimum 8 characters |

**Expected Result — Success**
- Status Code: `200 OK`
- Response Body:
```json
{ "status": "ok" }
```

**Expected Result — Negative Scenarios**

| Scenario | Status Code | Response Body |
|---|---|---|
| Username already registered | `409` | `{ "detail": "username already in use" }` |
| Username shorter than 3 characters | `422` | Pydantic validation error array |
| Password shorter than 8 characters | `422` | Pydantic validation error array |

**Postman Test Script**
```javascript
pm.test("Status is 200 or 409 (already signed up)", () => {
    pm.expect([200, 409]).to.include(pm.response.code);
});
```

---

#### TC-A2 — User Log In

| Field | Detail |
|---|---|
| Endpoint | `POST {{base_url}}/api/auth/login` |
| Purpose | Authenticate a regular user and establish a session |
| Authentication | None |
| Rate Limit | 10 requests / minute per IP |

**Request Body**
```json
{
  "username": "{{user_username}}",
  "password": "{{user_password}}"
}
```

**Expected Result — Success**
- Status Code: `200 OK`
- Response Body: `{ "status": "ok" }`
- Side Effect: `Set-Cookie: user_session=<token>; HttpOnly; Secure; SameSite=Strict; Max-Age=1800`

**Expected Result — Negative Scenarios**

| Scenario | Status Code | Response Body |
|---|---|---|
| Unknown username | `401` | `{ "detail": "invalid credentials" }` |
| Wrong password | `401` | `{ "detail": "invalid credentials" }` (identical message — prevents username enumeration) |

**Postman Test Script**
```javascript
pm.test("Status is 200", () => pm.response.to.have.status(200));
pm.test("user_session cookie is set", () => {
    pm.expect(pm.cookies.has("user_session")).to.be.true;
});
```

---

#### TC-A3 — Confirm Logged-In User Identity

| Field | Detail |
|---|---|
| Endpoint | `GET {{base_url}}/api/auth/me` |
| Purpose | Verify the current session belongs to the expected user |
| Authentication | `user_session` cookie required |
| Rate Limit | None |

**Request Body:** none

**Expected Result — Success**
- Status Code: `200 OK`
- Response Body:
```json
{ "id": "665f1a2b3c4d5e6f7a8b9c0d", "username": "alice" }
```

**Expected Result — Negative Scenarios**

| Scenario | Status Code | Response Body |
|---|---|---|
| No cookie sent / not logged in | `401` | `{ "detail": "not authenticated" }` |
| Session expired | `401` | `{ "detail": "session expired or invalid" }` |

**Postman Test Script**
```javascript
pm.test("Status is 200", () => pm.response.to.have.status(200));
pm.test("username matches", () => {
    pm.expect(pm.response.json().username).to.eql(pm.environment.get("user_username"));
});
```

---

#### TC-A4 — Submit an Aadhaar Number

| Field | Detail |
|---|---|
| Endpoint | `POST {{base_url}}/api/aadhaar` |
| Purpose | Encrypt and store an Aadhaar number under the currently logged-in user |
| Authentication | `user_session` cookie required |
| Rate Limit | 5 requests / minute per IP |

**Request Body**
```json
{
  "aadhaar_number": "102938475615",
  "consent": true,
  "ts": "{{$isoTimestamp}}"
}
```

**Field Validation Rules**

| Field | Type | Rule |
|---|---|---|
| `aadhaar_number` | string | exactly 12 digits, and the last digit must satisfy the Verhoeff checksum |
| `consent` | boolean | must be exactly `true` — no meaningful default, explicit informed consent |
| `ts` | ISO-8601 datetime | must be timezone-aware, and within ±5 minutes of server time |

`{{$isoTimestamp}}` is a Postman built-in dynamic variable that always resolves to the current UTC time in ISO-8601 format, so the freshness check never fails due to a stale hardcoded value.

**Expected Result — Success**
- Status Code: `200 OK`
- Response Body:
```json
{ "reference_id": "10BE3DBFBD69C9E5C554B68F29685DDDD593CD639DE4", "masked_preview": "XXXX-XXXX-5615" }
```
- Note: resubmitting the *same* Aadhaar number returns the **same** `reference_id` — it is not re-encrypted or duplicated.

**Expected Result — Negative Scenarios**

| Scenario | Status Code | Response Body |
|---|---|---|
| Not logged in | `401` | `{ "detail": "not authenticated" }` |
| Aadhaar number fails Verhoeff checksum | `400` | `{ "detail": "invalid Aadhaar number" }` |
| `ts` older than 5 minutes | `400` | `{ "detail": "request_expired" }` |
| `ts` more than 5 minutes in the future | `400` | `{ "detail": "timestamp_in_future" }` |
| `consent` is not `true`, or `ts` has no timezone | `422` | Pydantic validation error array |
| No admin registered on this deployment yet | `503` | `{ "detail": "no admin is registered yet — submissions are not accepted" }` |

**Postman Test Script**
```javascript
pm.test("Status is 200", () => pm.response.to.have.status(200));
if (pm.response.code === 200) {
    pm.environment.set("reference_id", pm.response.json().reference_id);
}
```

---

#### TC-A5 — List My Submissions

| Field | Detail |
|---|---|
| Endpoint | `GET {{base_url}}/api/my-submissions` |
| Purpose | Retrieve the logged-in user's own submission history (masked, never plaintext) |
| Authentication | `user_session` cookie required |
| Rate Limit | None |

**Request Body:** none

**Expected Result — Success**
- Status Code: `200 OK`
- Response Body:
```json
[
  { "id": "10BE3DBFBD69C9E5C554B68F29685DDDD593CD639DE4", "created_at": "2026-08-04T06:01:06.466Z", "masked_preview": "XXXX-XXXX-5615" }
]
```

**Expected Result — Negative Scenarios**

| Scenario | Status Code | Response Body |
|---|---|---|
| Not logged in | `401` | `{ "detail": "not authenticated" }` |

**Postman Test Script**
```javascript
pm.test("Status is 200", () => pm.response.to.have.status(200));
pm.test("Response is an array", () => pm.expect(pm.response.json()).to.be.an("array"));
```

---

#### TC-A6 — User Log Out

| Field | Detail |
|---|---|
| Endpoint | `POST {{base_url}}/api/auth/logout` |
| Purpose | Destroy the current user session |
| Authentication | None required (safe to call with or without a session) |
| Rate Limit | None |

**Request Body:** none

**Expected Result — Success**
- Status Code: `200 OK`
- Response Body: `{ "status": "ok" }`
- Side Effect: `user_session` cookie cleared; subsequent calls to TC-A3/A4/A5 return `401` until logging in again.

**Postman Test Script**
```javascript
pm.test("Status is 200", () => pm.response.to.have.status(200));
```

---

### 5.2 Module B — Admin Registration (First Admin)

Registers the first-ever (master) admin for a fresh deployment. Only succeeds once per deployment; requires the server-side `ADMIN_SETUP_TOKEN` secret.

#### TC-B1 — Check Registration Status

| Field | Detail |
|---|---|
| Endpoint | `GET {{base_url}}/api/admin/register/status` |
| Purpose | Determine whether any admin already exists on this deployment |
| Authentication | None |
| Rate Limit | None |

**Request Body:** none

**Expected Result — Success**
- Status Code: `200 OK`
- Response Body:
```json
{ "registered": false }
```
(or `{ "registered": true }` if a master admin already exists)

**Postman Test Script**
```javascript
pm.test("Status is 200", () => pm.response.to.have.status(200));
```

---

#### TC-B2 — Start Master Admin Registration

| Field | Detail |
|---|---|
| Endpoint | `POST {{base_url}}/api/admin/register/start` |
| Purpose | Begin master-admin self-registration; generates a TOTP secret to enroll |
| Authentication | None (authorized via `setup_token` in the body) |
| Rate Limit | 5 requests / minute per IP |

**Request Body**
```json
{
  "setup_token": "{{setup_token}}",
  "username": "{{admin_username}}",
  "password": "{{admin_password}}"
}
```

**Field Validation Rules**

| Field | Type | Rule |
|---|---|---|
| `setup_token` | string | must exactly match `ADMIN_SETUP_TOKEN` configured on the server |
| `username` | string | minimum 3 characters |
| `password` | string | minimum 12 characters |

**Expected Result — Success**
- Status Code: `200 OK`
- Response Body:
```json
{
  "registration_token": "8f2a1c9e...",
  "otpauth_uri": "otpauth://totp/Secure%20Aadhaar%20System:admin?secret=JBSWY3DPEHPK3PXP&issuer=...",
  "manual_secret": "JBSWY3DPEHPK3PXP",
  "qr_code_png_base64": "iVBORw0KGgoAAAANSUhEUgA..."
}
```
To scan the QR: paste `qr_code_png_base64` into a browser address bar prefixed with `data:image/png;base64,`. Alternatively, enter `manual_secret` into an authenticator app's "enter code manually" option.

**Expected Result — Negative Scenarios**

| Scenario | Status Code | Response Body |
|---|---|---|
| `setup_token` doesn't match server's `ADMIN_SETUP_TOKEN` | `403` | `{ "detail": "invalid setup token" }` |
| An admin already exists | `409` | `{ "detail": "an admin already exists" }` |
| Username < 3 chars or password < 12 chars | `400` | `{ "detail": "<validation message>" }` |
| `ADMIN_SETUP_TOKEN` not configured on the server | `503` | `{ "detail": "admin registration is not configured on this server" }` |

**Postman Test Script**
```javascript
pm.test("Status is 200 or 409 (already registered)", () => {
    pm.expect([200, 409]).to.include(pm.response.code);
});
if (pm.response.code === 200) {
    const body = pm.response.json();
    pm.environment.set("registration_token", body.registration_token);
    pm.environment.set("manual_secret", body.manual_secret);
    console.log("Enter this secret into your authenticator app:", body.manual_secret);
}
```

---

#### TC-B3 — Confirm Master Admin Registration

| Field | Detail |
|---|---|
| Endpoint | `POST {{base_url}}/api/admin/register/confirm` |
| Purpose | Prove TOTP enrollment succeeded before the admin account is persisted |
| Authentication | None (authorized via `registration_token`) |
| Rate Limit | 10 requests / minute per IP |

**Request Body**
```json
{
  "registration_token": "{{registration_token}}",
  "totp_code": "{{totp_code}}"
}
```

> Fill `totp_code` with a live 6-digit code from the authenticator app you seeded with `manual_secret` in TC-B2, and send immediately.

**Expected Result — Success**
- Status Code: `200 OK`
- Response Body: `{ "status": "ok" }`

**Expected Result — Negative Scenarios**

| Scenario | Status Code | Response Body |
|---|---|---|
| Wrong/expired TOTP code | `401` | `{ "detail": "invalid authenticator code" }` |
| Unknown or expired `registration_token` (10-minute TTL) | `404` | `{ "detail": "unknown or expired registration" }` |
| An admin already exists (race condition) | `409` | `{ "detail": "an admin already exists" }` |

**Postman Test Script**
```javascript
pm.test("Status is 200", () => pm.response.to.have.status(200));
```

---

### 5.3 Module C — Admin Session, Submissions & Decryption

Requires a registered admin (Module B, or a pre-existing deployment). Covers admin login, session confirmation, submission listing, decryption, and logout.

#### TC-C1 — Admin Log In

| Field | Detail |
|---|---|
| Endpoint | `POST {{base_url}}/api/admin/login` |
| Purpose | Authenticate an admin using password + TOTP + identity unlock (3-factor) |
| Authentication | None |
| Rate Limit | None |

**Request Body**
```json
{
  "username": "{{admin_username}}",
  "password": "{{admin_password}}",
  "totp_code": "{{totp_code}}"
}
```

> Fill `totp_code` with a fresh code immediately before sending. The resulting session idles out after 5 minutes — proceed through the rest of Module C promptly.

**Expected Result — Success**
- Status Code: `200 OK`
- Response Body: `{ "status": "ok" }`
- Side Effect: `Set-Cookie: admin_session=<token>; HttpOnly; Secure; SameSite=Strict; Max-Age=300`

**Expected Result — Negative Scenarios**

| Scenario | Status Code | Response Body |
|---|---|---|
| Unknown username | `401` | `{ "detail": "invalid credentials" }` |
| Wrong password | `401` | `{ "detail": "invalid credentials" }` |
| Wrong/expired TOTP code | `401` | `{ "detail": "invalid credentials" }` |
| Account disabled | `401` | `{ "detail": "invalid credentials" }` |

All four negative scenarios return an identical message and status code, by design, so an attacker cannot distinguish which factor was wrong.

**Postman Test Script**
```javascript
pm.test("Status is 200", () => pm.response.to.have.status(200));
pm.test("admin_session cookie is set", () => {
    pm.expect(pm.cookies.has("admin_session")).to.be.true;
});
```

---

#### TC-C2 — Confirm Admin Identity

| Field | Detail |
|---|---|
| Endpoint | `GET {{base_url}}/api/admin/me` |
| Purpose | Verify the current admin session and its role |
| Authentication | `admin_session` cookie required |
| Rate Limit | None |

**Request Body:** none

**Expected Result — Success**
- Status Code: `200 OK`
- Response Body:
```json
{ "id": "665f1a2b3c4d5e6f7a8b9c0d", "username": "admin", "role": "master" }
```
`role` is `"master"` or `"sub"` — determines access to Module D.

**Expected Result — Negative Scenarios**

| Scenario | Status Code | Response Body |
|---|---|---|
| Not logged in / session expired | `401` | `{ "detail": "not authenticated" }` or `{ "detail": "session expired or invalid" }` |

**Postman Test Script**
```javascript
pm.test("Status is 200", () => pm.response.to.have.status(200));
```

---

#### TC-C3 — List All Submissions

| Field | Detail |
|---|---|
| Endpoint | `GET {{base_url}}/api/admin/submissions` |
| Purpose | List every submission in the system (masked only), newest first |
| Authentication | `admin_session` cookie required (any role) |
| Rate Limit | None |

**Request Body:** none

**Expected Result — Success**
- Status Code: `200 OK`
- Response Body:
```json
[
  { "id": "10BE3DBFBD69C9E5C554B68F29685DDDD593CD639DE4", "created_at": "2026-08-04T06:01:06.466Z", "masked_preview": "XXXX-XXXX-5615" }
]
```

**Expected Result — Negative Scenarios**

| Scenario | Status Code | Response Body |
|---|---|---|
| Not logged in as admin | `401` | `{ "detail": "not authenticated" }` |

**Postman Test Script**
```javascript
pm.test("Status is 200", () => pm.response.to.have.status(200));
```

---

#### TC-C4 — Decrypt a Submission

| Field | Detail |
|---|---|
| Endpoint | `POST {{base_url}}/api/admin/submissions/{{reference_id}}/decrypt` |
| Purpose | Reveal the plaintext Aadhaar number for one record — the one moment it appears anywhere in the system |
| Authentication | `admin_session` cookie required; admin must hold a wrapped key for this specific record |
| Rate Limit | None |

**Request Body:** none. `reference_id` is a path parameter (auto-populated from TC-A4's Tests script).

**Expected Result — Success**
- Status Code: `200 OK`
- Response Body:
```json
{ "aadhaar_number": "102938475615" }
```
- Response Header: `Cache-Control: no-store`
- Side Effect: a `decrypt` event is written to the audit log with `result: "success"` and the caller's username.

**Expected Result — Negative Scenarios**

| Scenario | Status Code | Response Body |
|---|---|---|
| Unknown `reference_id` | `404` | `{ "detail": "not found" }` |
| Container signature failed verification | `400` | `{ "detail": "bad_signature" }` |
| This admin has no wrapped key for this record, or decryption otherwise failed | `400` | `{ "detail": "crypto_error" }` |
| Not logged in as admin | `401` | `{ "detail": "not authenticated" }` |

Both `400` scenarios also write a `decrypt` audit event with the corresponding failure `result`.

**Postman Test Script**
```javascript
pm.test("Status is 200", () => pm.response.to.have.status(200));
```

---

#### TC-C5 — Admin Log Out

| Field | Detail |
|---|---|
| Endpoint | `POST {{base_url}}/api/admin/logout` |
| Purpose | Destroy the admin session and release the in-memory unlocked private key |
| Authentication | None required |
| Rate Limit | None |

**Request Body:** none

**Expected Result — Success**
- Status Code: `200 OK`
- Response Body: `{ "status": "ok" }`
- Side Effect: `admin_session` cookie cleared; TC-C2/C3/C4 return `401` until logging in again.

**Postman Test Script**
```javascript
pm.test("Status is 200", () => pm.response.to.have.status(200));
```

---

### 5.4 Module D — Sub-Admin Management (Master Only)

**Prerequisite:** be logged in as **master** (TC-C1, with `role: "master"` confirmed via TC-C2). All three endpoints below return `403` for a `"sub"` admin.

#### TC-D1 — Start Sub-Admin Creation

| Field | Detail |
|---|---|
| Endpoint | `POST {{base_url}}/api/admin/admins/start` |
| Purpose | Begin creating a new sub-admin account |
| Authentication | `admin_session` cookie, role = `master` |
| Rate Limit | 10 requests / minute per IP |

**Request Body**
```json
{
  "username": "{{sub_admin_username}}",
  "password": "{{sub_admin_password}}"
}
```

**Field Validation Rules**

| Field | Type | Rule |
|---|---|---|
| `username` | string | minimum 3 characters |
| `password` | string | minimum 12 characters |

**Expected Result — Success**
- Status Code: `200 OK`
- Response Body: identical shape to TC-B2 (`registration_token`, `otpauth_uri`, `manual_secret`, `qr_code_png_base64`) — this is the new sub-admin's own QR code.

**Expected Result — Negative Scenarios**

| Scenario | Status Code | Response Body |
|---|---|---|
| Username already in use | `409` | `{ "detail": "username already in use" }` |
| Username < 3 chars or password < 12 chars | `400` | `{ "detail": "<validation message>" }` |
| Caller is not a master admin | `403` | `{ "detail": "master admin only" }` |

**Postman Test Script**
```javascript
pm.test("Status is 200", () => pm.response.to.have.status(200));
if (pm.response.code === 200) {
    const body = pm.response.json();
    pm.environment.set("registration_token", body.registration_token);
    pm.environment.set("manual_secret", body.manual_secret);
}
```

---

#### TC-D2 — Confirm Sub-Admin Creation

| Field | Detail |
|---|---|
| Endpoint | `POST {{base_url}}/api/admin/admins/confirm` |
| Purpose | Finalize sub-admin creation; retroactively re-wraps every existing record's key for the new sub-admin |
| Authentication | `admin_session` cookie, role = `master` |
| Rate Limit | 15 requests / minute per IP |

**Request Body**
```json
{
  "registration_token": "{{registration_token}}",
  "totp_code": "{{totp_code}}"
}
```

> Fill `totp_code` with a live code from the **sub-admin's** authenticator (seeded with `manual_secret` from TC-D1).

**Expected Result — Success**
- Status Code: `200 OK`
- Response Body:
```json
{ "admin_id": "665f1a2b3c4d5e6f7a8b9c0e", "containers_granted": 3 }
```
`containers_granted` is the number of pre-existing records retroactively re-wrapped for this new sub-admin.

**Expected Result — Negative Scenarios**

| Scenario | Status Code | Response Body |
|---|---|---|
| Wrong/expired TOTP code | `401` | `{ "detail": "invalid authenticator code" }` |
| Unknown or expired `registration_token` | `404` | `{ "detail": "unknown or expired registration" }` |
| Caller is not a master admin | `403` | `{ "detail": "master admin only" }` |

**Postman Test Script**
```javascript
pm.test("Status is 200", () => pm.response.to.have.status(200));
if (pm.response.code === 200) {
    pm.environment.set("sub_admin_id", pm.response.json().admin_id);
}
```

---

#### TC-D3 — List All Admins

| Field | Detail |
|---|---|
| Endpoint | `GET {{base_url}}/api/admin/admins` |
| Purpose | List every admin account (master and sub) with status |
| Authentication | `admin_session` cookie, role = `master` |
| Rate Limit | None |

**Request Body:** none

**Expected Result — Success**
- Status Code: `200 OK`
- Response Body:
```json
[
  { "id": "665f...", "username": "admin", "role": "master", "status": "active", "created_at": "2026-07-01T09:00:00Z", "created_by": null },
  { "id": "665f...", "username": "sub1", "role": "sub", "status": "active", "created_at": "2026-08-04T06:02:00Z", "created_by": "665f..." }
]
```

**Expected Result — Negative Scenarios**

| Scenario | Status Code | Response Body |
|---|---|---|
| Caller is not a master admin | `403` | `{ "detail": "master admin only" }` |
| Not logged in | `401` | `{ "detail": "not authenticated" }` |

**Postman Test Script**
```javascript
pm.test("Status is 200", () => pm.response.to.have.status(200));
```

**Supplementary manual steps for full Module D coverage (optional, recommended):**
1. Run TC-C5 to log out of the master session.
2. Run TC-C1 again using `sub_admin_username` / `sub_admin_password` / a fresh TOTP code from the sub-admin's authenticator, to confirm the sub-admin can log in independently.
3. Run TC-C4 against a `reference_id` that was submitted **before** the sub-admin was created. A `200` response proves the retroactive re-wrap from TC-D2 actually works, not just that `containers_granted` reported a number.

---

### 5.5 Module E — Audit Reporting & Logging

Available to **any** authenticated admin (master or sub) — no special role required.

#### TC-E1 — Date-Range Hit Report (JSON)

| Field | Detail |
|---|---|
| Endpoint | `GET {{base_url}}/api/admin/audit-report?from_date={{from_date}}&to_date={{to_date}}` |
| Purpose | List every submit/decrypt hit against Aadhaar records in a date range |
| Authentication | `admin_session` cookie required (any role) |
| Rate Limit | None |

**Query Parameters**

| Parameter | Type | Rule |
|---|---|---|
| `from_date` | `YYYY-MM-DD` | required, inclusive |
| `to_date` | `YYYY-MM-DD` | required, inclusive |

**Request Body:** none

**Expected Result — Success**
- Status Code: `200 OK`
- Response Body:
```json
[
  { "date": "2026-08-04", "reference_id": "10BE3DBFBD69...", "masked_aadhaar_no": "XXXX-XXXX-5615", "request_datetime": "2026-08-04T06:01:06.466Z" },
  { "date": "2026-08-05", "reference_id": null, "masked_aadhaar_no": null, "request_datetime": null }
]
```
This is a **one row per hit** report, not one row per record: a record submitted once and later decrypted twice produces three rows, each with its own `request_datetime`. Dates with zero hits still return a single placeholder row with all other fields `null`, so gaps in coverage remain visible.

**Expected Result — Negative Scenarios**

| Scenario | Status Code | Response Body |
|---|---|---|
| `from_date` is after `to_date` | `400` | `{ "detail": "from_date must not be after to_date" }` |
| Unparseable date | `422` | Pydantic validation error array |
| Not logged in as admin | `401` | `{ "detail": "not authenticated" }` |

**Postman Test Script**
```javascript
pm.test("Status is 200", () => pm.response.to.have.status(200));
```

---

#### TC-E2 — Date-Range Report as PDF

| Field | Detail |
|---|---|
| Endpoint | `GET {{base_url}}/api/admin/audit-report/pdf?from_date={{from_date}}&to_date={{to_date}}` |
| Purpose | Export the same hit report as a formatted, downloadable PDF |
| Authentication | `admin_session` cookie required (any role) |
| Rate Limit | None |

**Query Parameters**

| Parameter | Type | Rule |
|---|---|---|
| `from_date` | `YYYY-MM-DD` | required, inclusive |
| `to_date` | `YYYY-MM-DD` | required, inclusive |
| `columns` | comma-separated | optional; subset of `date`, `reference_id`, `masked_aadhaar_no`, `request_datetime`. Defaults to all four. |

**Request Body:** none

**Expected Result — Success**
- Status Code: `200 OK`
- Response Headers: `Content-Type: application/pdf`, `Content-Disposition: attachment; filename="audit-report_<from>_<to>.pdf"`
- Response Body: binary PDF, beginning with `%PDF`. All timestamps in the PDF are rendered in **IST (UTC+5:30)** and the timestamp column is explicitly labeled "Request Datetime (IST)".

> In Postman, use the dropdown next to the **Send** button and choose **Send and Download** to save the binary response to disk instead of viewing raw bytes in the response pane.

**Expected Result — Negative Scenarios**

| Scenario | Status Code | Response Body |
|---|---|---|
| `from_date` is after `to_date` | `400` | `{ "detail": "from_date must not be after to_date" }` |
| Unknown column name in `columns` | `400` | `{ "detail": "unknown column(s): <name>" }` |
| Empty `columns` value | `400` | `{ "detail": "at least one column must be selected" }` |
| Not logged in as admin | `401` | `{ "detail": "not authenticated" }` |

**Postman Test Script**
```javascript
pm.test("Status is 200", () => pm.response.to.have.status(200));
pm.test("Content-Type is application/pdf", () => {
    pm.expect(pm.response.headers.get("Content-Type")).to.eql("application/pdf");
});
```

---

#### TC-E3 — Full Audit Log

| Field | Detail |
|---|---|
| Endpoint | `GET {{base_url}}/api/admin/audit-log?from_date={{from_date}}&to_date={{to_date}}` |
| Purpose | List every login, logout, submission, and decrypt event in a date range, newest first |
| Authentication | `admin_session` cookie required (any role) |
| Rate Limit | None |

**Query Parameters**

| Parameter | Type | Rule |
|---|---|---|
| `from_date` | `YYYY-MM-DD` | required, inclusive |
| `to_date` | `YYYY-MM-DD` | required, inclusive |

**Request Body:** none

**Expected Result — Success**
- Status Code: `200 OK`
- Response Body:
```json
[
  { "ts": "2026-08-04T06:03:37.894Z", "action": "submit", "result": "success", "username": "test3", "container_id": "90BAA516A045..." },
  { "ts": "2026-08-04T06:02:00.341Z", "action": "admin_login", "result": "success", "username": "admin1", "container_id": null },
  { "ts": "2026-08-04T06:01:06.466Z", "action": "submit", "result": "success", "username": "test3", "container_id": "10BE3DBFBD69..." },
  { "ts": "2026-08-04T06:00:12.461Z", "action": "user_login", "result": "success", "username": "test3", "container_id": null }
]
```
`action` is one of `admin_login`, `admin_logout`, `user_login`, `user_logout`, `submit`, `decrypt`. `result` is `success` for logouts, and for the rest is either `success` or a short failure reason (`invalid_credentials`, `invalid_aadhaar_number`, `request_expired`, `timestamp_in_future`, `no_active_admins`, `bad_signature`, `crypto_error`).

**Expected Result — Negative Scenarios**

| Scenario | Status Code | Response Body |
|---|---|---|
| `from_date` is after `to_date` | `400` | `{ "detail": "from_date must not be after to_date" }` |
| Not logged in as admin | `401` | `{ "detail": "not authenticated" }` |

**Postman Test Script**
```javascript
pm.test("Status is 200", () => pm.response.to.have.status(200));
pm.test("Events are newest first", () => {
    const timestamps = pm.response.json().map(e => e.ts);
    pm.expect(timestamps).to.eql([...timestamps].sort().reverse());
});
```

---

## 6. Test Data Reference

| Purpose | Value |
|---|---|
| Valid test Aadhaar numbers | `102938475615`, `564738291043`, `999888777669` |
| Minimum regular-user username length | 3 characters |
| Minimum regular-user password length | 8 characters |
| Minimum admin username length | 3 characters |
| Minimum admin/sub-admin password length | 12 characters |
| TOTP code format | exactly 6 digits, rotates every 30 seconds |
| Submission freshness window (`ts` field) | ±5 minutes of server time |
| Pending registration token TTL | 10 minutes |

---

## 7. Appendix A — Full Endpoint Reference

| # | Method | Path | Auth | Rate Limit | Test Case |
|---|---|---|---|---|---|
| 1 | GET | `/health` | None | — | TC-00 |
| 2 | POST | `/api/auth/signup` | None | 10/min | TC-A1 |
| 3 | POST | `/api/auth/login` | None | 10/min | TC-A2 |
| 4 | GET | `/api/auth/me` | user session | — | TC-A3 |
| 5 | POST | `/api/aadhaar` | user session | 5/min | TC-A4 |
| 6 | GET | `/api/my-submissions` | user session | — | TC-A5 |
| 7 | POST | `/api/auth/logout` | none required | — | TC-A6 |
| 8 | GET | `/api/admin/register/status` | None | — | TC-B1 |
| 9 | POST | `/api/admin/register/start` | setup token | 5/min | TC-B2 |
| 10 | POST | `/api/admin/register/confirm` | registration token | 10/min | TC-B3 |
| 11 | POST | `/api/admin/login` | None | — | TC-C1 |
| 12 | GET | `/api/admin/me` | admin session | — | TC-C2 |
| 13 | GET | `/api/admin/submissions` | admin session | — | TC-C3 |
| 14 | POST | `/api/admin/submissions/{id}/decrypt` | admin session | — | TC-C4 |
| 15 | POST | `/api/admin/logout` | none required | — | TC-C5 |
| 16 | POST | `/api/admin/admins/start` | admin session, master only | 10/min | TC-D1 |
| 17 | POST | `/api/admin/admins/confirm` | admin session, master only | 15/min | TC-D2 |
| 18 | GET | `/api/admin/admins` | admin session, master only | — | TC-D3 |
| 19 | GET | `/api/admin/audit-report` | admin session | — | TC-E1 |
| 20 | GET | `/api/admin/audit-report/pdf` | admin session | — | TC-E2 |
| 21 | GET | `/api/admin/audit-log` | admin session | — | TC-E3 |

---

## 8. Appendix B — Environment Variable Reference

Repeated here for a single point of reference (see also Section 3.2).

| Variable | Example Value | Populated By |
|---|---|---|
| `base_url` | `http://localhost:8000` | Manual |
| `setup_token` | *(from `ADMIN_SETUP_TOKEN`)* | Manual |
| `totp_code` | `123456` | Manual, per request |
| `user_username` | `alice` | Manual |
| `user_password` | `a-strong-password-1` | Manual |
| `admin_username` | `admin` | Manual |
| `admin_password` | `at-least-12-characters` | Manual |
| `sub_admin_username` | `sub1` | Manual |
| `sub_admin_password` | `at-least-12-characters-2` | Manual |
| `registration_token` | *(auto)* | TC-B2 / TC-D1 Tests script |
| `manual_secret` | *(auto)* | TC-B2 / TC-D1 Tests script |
| `reference_id` | *(auto)* | TC-A4 Tests script |
| `sub_admin_id` | *(auto)* | TC-D2 Tests script |
| `from_date` | `2026-08-01` | Manual |
| `to_date` | `2026-08-31` | Manual |

---

## 9. Appendix C — Test Execution Log Template

Copy this table into a tracking sheet when executing a full pass.

| Test Case ID | Endpoint | Executed By | Date | Result (Pass/Fail) | Notes |
|---|---|---|---|---|---|
| TC-00 | GET /health | | | | |
| TC-A1 | POST /api/auth/signup | | | | |
| TC-A2 | POST /api/auth/login | | | | |
| TC-A3 | GET /api/auth/me | | | | |
| TC-A4 | POST /api/aadhaar | | | | |
| TC-A5 | GET /api/my-submissions | | | | |
| TC-A6 | POST /api/auth/logout | | | | |
| TC-B1 | GET /api/admin/register/status | | | | |
| TC-B2 | POST /api/admin/register/start | | | | |
| TC-B3 | POST /api/admin/register/confirm | | | | |
| TC-C1 | POST /api/admin/login | | | | |
| TC-C2 | GET /api/admin/me | | | | |
| TC-C3 | GET /api/admin/submissions | | | | |
| TC-C4 | POST /api/admin/submissions/{id}/decrypt | | | | |
| TC-C5 | POST /api/admin/logout | | | | |
| TC-D1 | POST /api/admin/admins/start | | | | |
| TC-D2 | POST /api/admin/admins/confirm | | | | |
| TC-D3 | GET /api/admin/admins | | | | |
| TC-E1 | GET /api/admin/audit-report | | | | |
| TC-E2 | GET /api/admin/audit-report/pdf | | | | |
| TC-E3 | GET /api/admin/audit-log | | | | |

---

## 10. Revision History

| Version | Date | Author | Summary of Changes |
|---|---|---|---|
| 1.0 | 2026-08-04 | QA / Backend Team | Initial full test guide covering all 21 endpoints across 6 modules |
