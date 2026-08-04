import { useCallback, useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  ApiError,
  AUDIT_REPORT_PDF_COLUMNS,
  downloadAuditReportPdf,
  getAuditLog,
  getAuditReport,
  type AuditLogEvent,
  type AuditReportPdfColumn,
  type AuditReportRow,
} from "../api/client";

function todayIso(): string {
  return new Date().toISOString().slice(0, 10);
}

// Fixed to IST regardless of the viewer's own OS/browser timezone, so this
// always agrees with the PDF export (which is also always IST) rather than
// silently drifting if an admin's machine is set to a different zone.
function formatIst(iso: string): string {
  return new Date(iso).toLocaleString("en-IN", {
    timeZone: "Asia/Kolkata",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
}

const ALL_PDF_COLUMNS = AUDIT_REPORT_PDF_COLUMNS.map((c) => c.key);

export default function AdminAuditReport() {
  const navigate = useNavigate();
  const [fromDate, setFromDate] = useState(todayIso());
  const [toDate, setToDate] = useState(todayIso());
  const [rows, setRows] = useState<AuditReportRow[] | null>(null);
  const [events, setEvents] = useState<AuditLogEvent[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [pdfColumns, setPdfColumns] = useState<AuditReportPdfColumn[]>([...ALL_PDF_COLUMNS]);
  const [pdfError, setPdfError] = useState<string | null>(null);
  const [downloadingPdf, setDownloadingPdf] = useState(false);

  const goToLogin = useCallback(() => {
    navigate("/admin/login");
  }, [navigate]);

  async function handleRun(e: FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const [reportData, eventData] = await Promise.all([
        getAuditReport(fromDate, toDate),
        getAuditLog(fromDate, toDate),
      ]);
      setRows(reportData);
      setEvents(eventData);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        goToLogin();
        return;
      }
      setError(
        err instanceof ApiError
          ? err.status === 400
            ? "From Date must not be after To Date."
            : "Failed to load the audit report."
          : "Could not reach the server.",
      );
      setRows(null);
      setEvents(null);
    } finally {
      setLoading(false);
    }
  }

  function toggleColumn(key: AuditReportPdfColumn) {
    setPdfColumns((prev) => (prev.includes(key) ? prev.filter((c) => c !== key) : [...prev, key]));
  }

  async function handleDownloadPdf() {
    if (pdfColumns.length === 0) {
      setPdfError("Select at least one column.");
      return;
    }
    setDownloadingPdf(true);
    setPdfError(null);
    try {
      const blob = await downloadAuditReportPdf(fromDate, toDate, pdfColumns);
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = `audit-report_${fromDate}_${toDate}.pdf`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        goToLogin();
        return;
      }
      setPdfError(
        err instanceof ApiError
          ? err.status === 400
            ? "From Date must not be after To Date."
            : "Failed to generate the PDF."
          : "Could not reach the server.",
      );
    } finally {
      setDownloadingPdf(false);
    }
  }

  return (
    <div className="dashboard-page">
      <div className="dashboard-header">
        <h1>Audit Report</h1>
        <div className="dashboard-actions">
          <Link to="/admin">
            <button type="button">Back to Dashboard</button>
          </Link>
        </div>
      </div>

      <form onSubmit={handleRun} style={{ display: "flex", gap: "1rem", alignItems: "flex-end", marginBottom: "1.5rem" }}>
        <div>
          <label htmlFor="from-date">From Date</label>
          <br />
          <input
            id="from-date"
            type="date"
            value={fromDate}
            onChange={(e) => setFromDate(e.target.value)}
            required
          />
        </div>
        <div>
          <label htmlFor="to-date">To Date</label>
          <br />
          <input id="to-date" type="date" value={toDate} onChange={(e) => setToDate(e.target.value)} required />
        </div>
        <button type="submit" disabled={loading}>
          {loading ? "Running..." : "Run Report"}
        </button>
      </form>

      {error && <p className="error-text">{error}</p>}

      {rows && (
        rows.length === 0 ? (
          <p>No dates in range.</p>
        ) : (
          <table className="submissions-table">
            <thead>
              <tr>
                <th>Date</th>
                <th>Reference ID</th>
                <th>Masked Aadhaar No</th>
                <th>Request Datetime (IST)</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row, i) => (
                // The same reference_id can now appear more than once on the same date
                // (e.g. two decrypts the same day) — each row is its own hit, so the
                // index is part of the key, not a fallback for a missing reference_id.
                <tr key={`${row.date}-${row.reference_id ?? "none"}-${i}`}>
                  <td>{row.date}</td>
                  <td>{row.reference_id ? <code>{row.reference_id}</code> : <span className="hidden-value">—</span>}</td>
                  <td>{row.masked_aadhaar_no ? <code>{row.masked_aadhaar_no}</code> : <span className="hidden-value">—</span>}</td>
                  <td>{row.request_datetime ? formatIst(row.request_datetime) : <span className="hidden-value">—</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )
      )}

      {rows && (
        <div style={{ marginTop: "1.5rem" }}>
          <h2>Download PDF</h2>
          <div style={{ display: "flex", gap: "1rem", flexWrap: "wrap", marginBottom: "0.75rem" }}>
            {AUDIT_REPORT_PDF_COLUMNS.map((col) => (
              <label key={col.key} style={{ display: "flex", alignItems: "center", gap: "0.35rem" }}>
                <input
                  type="checkbox"
                  checked={pdfColumns.includes(col.key)}
                  onChange={() => toggleColumn(col.key)}
                />
                {col.label}
              </label>
            ))}
          </div>
          {pdfError && <p className="error-text">{pdfError}</p>}
          <button type="button" onClick={handleDownloadPdf} disabled={downloadingPdf}>
            {downloadingPdf ? "Generating..." : "Download PDF"}
          </button>
        </div>
      )}

      {events && (
        <div style={{ marginTop: "2rem" }}>
          <h2>Audit Log Events</h2>
          {events.length === 0 ? (
            <p>No events in range.</p>
          ) : (
            <table className="submissions-table">
              <thead>
                <tr>
                  <th>Timestamp (IST)</th>
                  <th>Action</th>
                  <th>Result</th>
                  <th>Username</th>
                </tr>
              </thead>
              <tbody>
                {events.map((event, i) => (
                  <tr key={`${event.ts}-${i}`}>
                    <td>{formatIst(event.ts)}</td>
                    <td>{event.action}</td>
                    <td>{event.result}</td>
                    <td>{event.username ?? <span className="hidden-value">—</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  );
}
