import { useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ApiError, userLogin } from "../api/client";

export default function UserLogin() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const navigate = useNavigate();

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await userLogin(username, password);
      navigate("/");
    } catch (err) {
      setError(
        err instanceof ApiError && err.status === 401
          ? "Wrong username or password."
          : "Could not reach the server. Please try again.",
      );
    } finally {
      setSubmitting(false);
      setPassword("");
    }
  }

  return (
    <div className="page">
      <div className="card">
        <h1>Log In</h1>
        <p className="subtitle">Log in to submit an Aadhaar number and see your own submission history.</p>
        <form onSubmit={handleSubmit}>
          <label htmlFor="username">Username</label>
          <input
            id="username"
            type="text"
            autoComplete="username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            disabled={submitting}
          />

          <label htmlFor="password">Password</label>
          <input
            id="password"
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            disabled={submitting}
          />

          {error && <p className="error-text">{error}</p>}

          <button type="submit" disabled={submitting || username.length === 0 || password.length === 0}>
            {submitting ? "Logging in..." : "Log In"}
          </button>
        </form>
        <p className="subtitle" style={{ marginTop: "1.25rem", marginBottom: 0 }}>
          Don't have an account? <Link to="/signup">Sign up</Link>.
        </p>
      </div>
    </div>
  );
}
