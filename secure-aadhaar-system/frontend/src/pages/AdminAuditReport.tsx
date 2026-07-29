import { useCallback, useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ApiError, getAuditReport, type AuditReportRow } from "../api/client";

function todayIso(): string {
  return new Date().toISOString().slice(0, 10);
}

export default function AdminAuditReport() {
  const navigate = useNavigate();
  const [fromDate, setFromDate] = useState(todayIso());
  const [toDate, setToDate] = useState(todayIso());
  const [rows, setRows] = useState<AuditReportRow[] | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const goToLogin = useCallback(() => {
    navigate("/admin/login");
  }, [navigate]);

  async function handleRun(e: FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError(null);
    try {
      const data = await getAuditReport(fromDate, toDate);
      setRows(data);
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
    } finally {
      setLoading(false);
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
                <th>Unique Reference No</th>
                <th>Reference ID</th>
                <th>Masked Aadhaar No</th>
                <th>Request Datetime</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row, i) => (
                <tr key={`${row.date}-${row.reference_id ?? i}`}>
                  <td>{row.date}</td>
                  <td>{row.unique_reference_no ? <code>{row.unique_reference_no}</code> : <span className="hidden-value">—</span>}</td>
                  <td>{row.reference_id ? <code>{row.reference_id}</code> : <span className="hidden-value">—</span>}</td>
                  <td>{row.masked_aadhaar_no ? <code>{row.masked_aadhaar_no}</code> : <span className="hidden-value">—</span>}</td>
                  <td>{row.request_datetime ? new Date(row.request_datetime).toLocaleString() : <span className="hidden-value">—</span>}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )
      )}
    </div>
  );
}
