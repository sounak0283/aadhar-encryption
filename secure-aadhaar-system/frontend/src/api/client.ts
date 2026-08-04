/**
 * Thin fetch wrapper for the Secure Aadhaar Transmission System backend.
 * Always sends credentials (the admin session cookie is httpOnly, so this
 * is the only way the browser attaches it) and normalizes errors into
 * ApiError so callers can branch on status (e.g. 401 -> redirect to login).
 */
const API_BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "http://127.0.0.1:8000";

export class ApiError extends Error {
  status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...options,
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
      ...options.headers,
    },
  });

  if (!response.ok) {
    let detail = response.statusText;
    try {
      const body = (await response.json()) as { detail?: string };
      detail = body.detail ?? detail;
    } catch {
      // no JSON body to read
    }
    throw new ApiError(response.status, detail);
  }

  if (response.status === 204) {
    return undefined as T;
  }
  return (await response.json()) as T;
}

export interface SubmitAadhaarResponse {
  reference_id: string;
  masked_preview: string;
}

export interface SubmissionListItem {
  id: string;
  created_at: string;
  masked_preview: string;
}

export interface DecryptResponse {
  aadhaar_number: string;
}

export function submitAadhaar(aadhaarNumber: string, consent: boolean): Promise<SubmitAadhaarResponse> {
  return request<SubmitAadhaarResponse>("/api/aadhaar", {
    method: "POST",
    body: JSON.stringify({
      aadhaar_number: aadhaarNumber,
      consent,
      ts: new Date().toISOString(),
    }),
  });
}

export function adminLogin(username: string, password: string, totpCode: string): Promise<{ status: string }> {
  return request("/api/admin/login", {
    method: "POST",
    body: JSON.stringify({ username, password, totp_code: totpCode }),
  });
}

export function adminLogout(): Promise<{ status: string }> {
  return request("/api/admin/logout", { method: "POST" });
}

export interface MeResponse {
  id: string;
  username: string;
  role: "master" | "sub";
}

export function getMe(): Promise<MeResponse> {
  return request<MeResponse>("/api/admin/me");
}

export function listSubmissions(): Promise<SubmissionListItem[]> {
  return request<SubmissionListItem[]>("/api/admin/submissions");
}

export function decryptSubmission(id: string): Promise<DecryptResponse> {
  return request<DecryptResponse>(`/api/admin/submissions/${id}/decrypt`, {
    method: "POST",
  });
}

export interface RegisterStatusResponse {
  registered: boolean;
}

export interface RegisterStartResponse {
  registration_token: string;
  otpauth_uri: string;
  manual_secret: string;
  qr_code_png_base64: string;
}

export function getRegisterStatus(): Promise<RegisterStatusResponse> {
  return request<RegisterStatusResponse>("/api/admin/register/status");
}

export function registerStart(setupToken: string, username: string, password: string): Promise<RegisterStartResponse> {
  return request<RegisterStartResponse>("/api/admin/register/start", {
    method: "POST",
    body: JSON.stringify({ setup_token: setupToken, username, password }),
  });
}

export function registerConfirm(registrationToken: string, totpCode: string): Promise<{ status: string }> {
  return request("/api/admin/register/confirm", {
    method: "POST",
    body: JSON.stringify({ registration_token: registrationToken, totp_code: totpCode }),
  });
}

// ============================================================================
// Master-only: manage sub-admins
// ============================================================================

export interface AdminSummary {
  id: string;
  username: string;
  role: "master" | "sub";
  status: "active" | "disabled";
  created_at: string;
  created_by: string | null;
}

export function listAdmins(): Promise<AdminSummary[]> {
  return request<AdminSummary[]>("/api/admin/admins");
}

export function createSubAdminStart(username: string, password: string): Promise<RegisterStartResponse> {
  return request<RegisterStartResponse>("/api/admin/admins/start", {
    method: "POST",
    body: JSON.stringify({ username, password }),
  });
}

export interface CreateSubAdminConfirmResponse {
  admin_id: string;
  containers_granted: number;
}

export function createSubAdminConfirm(
  registrationToken: string,
  totpCode: string,
): Promise<CreateSubAdminConfirmResponse> {
  return request<CreateSubAdminConfirmResponse>("/api/admin/admins/confirm", {
    method: "POST",
    body: JSON.stringify({ registration_token: registrationToken, totp_code: totpCode }),
  });
}

// ============================================================================
// Regular (non-admin) user auth — the people submitting Aadhaar numbers
// ============================================================================

export interface UserMeResponse {
  id: string;
  username: string;
}

export interface MySubmissionListItem {
  id: string;
  created_at: string;
  masked_preview: string;
}

export function userSignup(username: string, password: string): Promise<{ status: string }> {
  return request("/api/auth/signup", {
    method: "POST",
    body: JSON.stringify({ username, password }),
  });
}

export function userLogin(username: string, password: string): Promise<{ status: string }> {
  return request("/api/auth/login", {
    method: "POST",
    body: JSON.stringify({ username, password }),
  });
}

export function userLogout(): Promise<{ status: string }> {
  return request("/api/auth/logout", { method: "POST" });
}

export function getUserMe(): Promise<UserMeResponse> {
  return request<UserMeResponse>("/api/auth/me");
}

export function listMySubmissions(): Promise<MySubmissionListItem[]> {
  return request<MySubmissionListItem[]>("/api/my-submissions");
}

// ============================================================================
// Admin: date-range audit report (backend-1 only)
// ============================================================================

export interface AuditReportRow {
  date: string;
  reference_id: string | null;
  masked_aadhaar_no: string | null;
  request_datetime: string | null;
}

export function getAuditReport(fromDate: string, toDate: string): Promise<AuditReportRow[]> {
  const params = new URLSearchParams({ from_date: fromDate, to_date: toDate });
  return request<AuditReportRow[]>(`/api/admin/audit-report?${params.toString()}`);
}

export const AUDIT_REPORT_PDF_COLUMNS = [
  { key: "date", label: "Date" },
  { key: "reference_id", label: "Reference ID" },
  { key: "masked_aadhaar_no", label: "Masked Aadhaar No" },
  { key: "request_datetime", label: "Request Datetime (IST)" },
] as const;

export type AuditReportPdfColumn = (typeof AUDIT_REPORT_PDF_COLUMNS)[number]["key"];

export async function downloadAuditReportPdf(
  fromDate: string,
  toDate: string,
  columns: AuditReportPdfColumn[],
): Promise<Blob> {
  const params = new URLSearchParams({ from_date: fromDate, to_date: toDate, columns: columns.join(",") });
  const response = await fetch(`${API_BASE_URL}/api/admin/audit-report/pdf?${params.toString()}`, {
    credentials: "include",
  });

  if (!response.ok) {
    let detail = response.statusText;
    try {
      const body = (await response.json()) as { detail?: string };
      detail = body.detail ?? detail;
    } catch {
      // no JSON body to read
    }
    throw new ApiError(response.status, detail);
  }
  return response.blob();
}

export interface AuditLogEvent {
  ts: string;
  action: string;
  result: string;
  username: string | null;
  container_id: string | null;
}

export function getAuditLog(fromDate: string, toDate: string): Promise<AuditLogEvent[]> {
  const params = new URLSearchParams({ from_date: fromDate, to_date: toDate });
  return request<AuditLogEvent[]>(`/api/admin/audit-log?${params.toString()}`);
}
