import { useCallback, useEffect, useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  ApiError,
  adminLogout,
  decryptSubmission,
  getMe,
  listSubmissions,
  type MeResponse,
  type SubmissionListItem,
} from "../api/client";

// Mirrors the backend's 5-minute sliding idle timeout (see
// backend/app/services/admin_session.py). This countdown is UX only — the
// server is the actual authority; a 401 on any call is what really matters.
const SESSION_TTL_SECONDS = 5 * 60;
const REVEAL_AUTO_HIDE_SECONDS = 15;

export default function AdminDashboard() {
  const navigate = useNavigate();
  const [items, setItems] = useState<SubmissionListItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [revealed, setRevealed] = useState<Record<string, string>>({});
  const [decryptingId, setDecryptingId] = useState<string | null>(null);
  const [secondsLeft, setSecondsLeft] = useState(SESSION_TTL_SECONDS);
  const [me, setMe] = useState<MeResponse | null>(null);
  const hideTimers = useRef<Record<string, ReturnType<typeof setTimeout>>>({});

  const goToLogin = useCallback(() => {
    navigate("/admin/login");
  }, [navigate]);

  const resetCountdown = useCallback(() => {
    setSecondsLeft(SESSION_TTL_SECONDS);
  }, []);

  const loadSubmissions = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await listSubmissions();
      setItems(data);
      resetCountdown();
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        goToLogin();
        return;
      }
      setError("Failed to load submissions.");
    } finally {
      setLoading(false);
    }
  }, [goToLogin, resetCountdown]);

  useEffect(() => {
    loadSubmissions();
    getMe()
      .then(setMe)
      .catch(() => {
        /* non-critical — the header just won't show the username/role if this fails */
      });
  }, [loadSubmissions]);

  useEffect(() => {
    const interval = setInterval(() => {
      setSecondsLeft((s) => {
        if (s <= 1) {
          goToLogin();
          return 0;
        }
        return s - 1;
      });
    }, 1000);
    return () => clearInterval(interval);
  }, [goToLogin]);

  useEffect(() => {
    const timers = hideTimers.current;
    return () => {
      Object.values(timers).forEach(clearTimeout);
    };
  }, []);

  async function handleShow(id: string) {
    setDecryptingId(id);
    setError(null);
    try {
      const result = await decryptSubmission(id);
      setRevealed((prev) => ({ ...prev, [id]: result.aadhaar_number }));
      resetCountdown();

      clearTimeout(hideTimers.current[id]);
      hideTimers.current[id] = setTimeout(() => {
        setRevealed((prev) => {
          const next = { ...prev };
          delete next[id];
          return next;
        });
      }, REVEAL_AUTO_HIDE_SECONDS * 1000);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        goToLogin();
        return;
      }
      setError("Failed to decrypt this record.");
    } finally {
      setDecryptingId(null);
    }
  }

  function handleHide(id: string) {
    clearTimeout(hideTimers.current[id]);
    setRevealed((prev) => {
      const next = { ...prev };
      delete next[id];
      return next;
    });
  }

  async function handleLogout() {
    try {
      await adminLogout();
    } finally {
      goToLogin();
    }
  }

  const minutes = Math.floor(secondsLeft / 60);
  const seconds = secondsLeft % 60;

  return (
    <div className="dashboard-page">
      <div className="dashboard-header">
        <h1>Admin Dashboard{me ? ` — ${me.username} (${me.role})` : ""}</h1>
        <div className="dashboard-actions">
          <span className={`countdown ${secondsLeft <= 30 ? "countdown-warning" : ""}`}>
            Session: {minutes}:{seconds.toString().padStart(2, "0")}
          </span>
          {me?.role === "master" && (
            <Link to="/admin/manage">
              <button type="button">Manage Admins</button>
            </Link>
          )}
          <Link to="/admin/audit-report">
            <button type="button">Audit Report</button>
          </Link>
          <button onClick={handleLogout}>Log Out</button>
        </div>
      </div>

      {error && <p className="error-text">{error}</p>}

      {loading ? (
        <p>Loading...</p>
      ) : items.length === 0 ? (
        <p>No submissions yet.</p>
      ) : (
        <table className="submissions-table">
          <thead>
            <tr>
              <th>Submitted</th>
              <th>Preview</th>
              <th>Aadhaar Number</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {items.map((item) => (
              <tr key={item.id}>
                <td>{new Date(item.created_at).toLocaleString()}</td>
                <td>
                  <code>{item.masked_preview}</code>
                </td>
                <td>
                  {revealed[item.id] ? (
                    <code className="revealed">{revealed[item.id]}</code>
                  ) : (
                    <span className="hidden-value">hidden</span>
                  )}
                </td>
                <td>
                  {revealed[item.id] ? (
                    <button onClick={() => handleHide(item.id)}>Hide</button>
                  ) : (
                    <button onClick={() => handleShow(item.id)} disabled={decryptingId === item.id}>
                      {decryptingId === item.id ? "Decrypting..." : "Show"}
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
