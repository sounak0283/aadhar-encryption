import { useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { adminLogin, ApiError } from "../api/client";

export default function AdminLogin() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [totpCode, setTotpCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const navigate = useNavigate();

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await adminLogin(username, password, totpCode);
      navigate("/admin");
    } catch (err) {
      setError(
        err instanceof ApiError && err.status === 401
          ? "Wrong username, password, or authenticator code."
          : "Could not reach the server. Please try again.",
      );
    } finally {
      // Never leave the password/code sitting in state after a submit attempt.
      setSubmitting(false);
      setPassword("");
      setTotpCode("");
    }
  }

  return (
    <div className="page">
      <div className="card">
        <h1>Admin Login</h1>
        <p className="subtitle">Password unlocks nothing by itself — the authenticator code is checked first.</p>
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

          <label htmlFor="totp">Authenticator Code</label>
          <input
            id="totp"
            type="text"
            inputMode="numeric"
            maxLength={6}
            autoComplete="one-time-code"
            placeholder="6-digit code"
            value={totpCode}
            onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, ""))}
            disabled={submitting}
          />

          {error && <p className="error-text">{error}</p>}

          <button
            type="submit"
            disabled={submitting || username.length === 0 || password.length === 0 || totpCode.length !== 6}
          >
            {submitting ? "Logging in..." : "Log In"}
          </button>
        </form>
        <p className="subtitle" style={{ marginTop: "1.25rem", marginBottom: 0 }}>
          First time setting this up? <Link to="/admin/register">Register the admin account</Link>.
        </p>
      </div>
    </div>
  );
}
