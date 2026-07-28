import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ApiError, listMySubmissions, type MySubmissionListItem } from "../api/client";

export default function MySubmissions() {
  const navigate = useNavigate();
  const [items, setItems] = useState<MySubmissionListItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    listMySubmissions()
      .then(setItems)
      .catch((err) => {
        if (err instanceof ApiError && err.status === 401) {
          navigate("/login");
          return;
        }
        setError("Failed to load your submissions.");
      })
      .finally(() => setLoading(false));
  }, [navigate]);

  return (
    <div className="dashboard-page">
      <div className="dashboard-header">
        <h1>My Submissions</h1>
        <div className="dashboard-actions">
          <Link to="/">
            <button type="button">Submit Another</button>
          </Link>
        </div>
      </div>

      {error && <p className="error-text">{error}</p>}

      {loading ? (
        <p>Loading...</p>
      ) : items.length === 0 ? (
        <p>You haven't submitted anything yet.</p>
      ) : (
        <table className="submissions-table">
          <thead>
            <tr>
              <th>Submitted</th>
              <th>Preview</th>
            </tr>
          </thead>
          <tbody>
            {items.map((item) => (
              <tr key={item.id}>
                <td>{new Date(item.created_at).toLocaleString()}</td>
                <td>
                  <code>{item.masked_preview}</code>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <p className="subtitle" style={{ marginTop: "1rem" }}>
        Only an authenticated admin can decrypt these — you're seeing the same masked preview they'd see before
        choosing to decrypt one.
      </p>
    </div>
  );
}
