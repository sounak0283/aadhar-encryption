import { useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ApiError, userLogin, userSignup } from "../api/client";

const MIN_USERNAME_LENGTH = 3;
const MIN_PASSWORD_LENGTH = 8;

export default function UserSignup() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const navigate = useNavigate();

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);

    if (username.length < MIN_USERNAME_LENGTH) {
      setError(`Username must be at least ${MIN_USERNAME_LENGTH} characters.`);
      return;
    }
    if (password.length < MIN_PASSWORD_LENGTH) {
      setError(`Password must be at least ${MIN_PASSWORD_LENGTH} characters.`);
      return;
    }
    if (password !== confirmPassword) {
      setError("Passwords do not match.");
      return;
    }

    setSubmitting(true);
    try {
      await userSignup(username, password);
      await userLogin(username, password); // sign up, then log straight in
      navigate("/");
    } catch (err) {
      if (err instanceof ApiError && err.status === 409) {
        setError("That username is already taken.");
      } else {
        setError("Something went wrong. Please try again.");
      }
    } finally {
      setSubmitting(false);
      setPassword("");
      setConfirmPassword("");
    }
  }

  return (
    <div className="page">
      <div className="card">
        <h1>Sign Up</h1>
        <p className="subtitle">Create an account to submit an Aadhaar number and see your own submission history.</p>
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
            autoComplete="new-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            disabled={submitting}
          />

          <label htmlFor="confirmPassword">Confirm Password</label>
          <input
            id="confirmPassword"
            type="password"
            autoComplete="new-password"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            disabled={submitting}
          />

          {error && <p className="error-text">{error}</p>}

          <button
            type="submit"
            disabled={submitting || username.length === 0 || password.length === 0 || confirmPassword.length === 0}
          >
            {submitting ? "Creating account..." : "Sign Up"}
          </button>
        </form>
        <p className="subtitle" style={{ marginTop: "1.25rem", marginBottom: 0 }}>
          Already have an account? <Link to="/login">Log in</Link>.
        </p>
      </div>
    </div>
  );
}
