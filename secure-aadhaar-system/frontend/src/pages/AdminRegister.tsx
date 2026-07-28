import { useEffect, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import {
  ApiError,
  getRegisterStatus,
  registerConfirm,
  registerStart,
  type RegisterStartResponse,
} from "../api/client";

type Step = "checking" | "already-registered" | "credentials" | "totp" | "done";

const MIN_USERNAME_LENGTH = 3;
const MIN_PASSWORD_LENGTH = 12;

export default function AdminRegister() {
  const [step, setStep] = useState<Step>("checking");
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  const [setupToken, setSetupToken] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");

  const [setup, setSetup] = useState<RegisterStartResponse | null>(null);
  const [totpCode, setTotpCode] = useState("");

  useEffect(() => {
    getRegisterStatus()
      .then((status) => setStep(status.registered ? "already-registered" : "credentials"))
      .catch(() => setStep("credentials")); // if the status check itself fails, let the form's own errors explain why
  }, []);

  async function handleCredentialsSubmit(e: FormEvent) {
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
      const result = await registerStart(setupToken, username, password);
      setSetup(result);
      setStep("totp");
    } catch (err) {
      if (err instanceof ApiError && err.status === 403) {
        setError("Invalid setup token.");
      } else if (err instanceof ApiError && err.status === 409) {
        setStep("already-registered");
      } else if (err instanceof ApiError && err.status === 503) {
        setError("Admin registration isn't configured on this server (ADMIN_SETUP_TOKEN not set).");
      } else {
        setError("Something went wrong. Please try again.");
      }
    } finally {
      setSubmitting(false);
      setSetupToken("");
      setPassword("");
      setConfirmPassword("");
    }
  }

  async function handleTotpSubmit(e: FormEvent) {
    e.preventDefault();
    if (!setup) return;
    setError(null);
    setSubmitting(true);
    try {
      await registerConfirm(setup.registration_token, totpCode);
      setStep("done");
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        setError("Wrong code. Try the current one from your authenticator app.");
      } else if (err instanceof ApiError && err.status === 404) {
        setError("This registration attempt expired. Please start over.");
        setStep("credentials");
        setSetup(null);
      } else if (err instanceof ApiError && err.status === 409) {
        setStep("already-registered");
      } else {
        setError("Something went wrong. Please try again.");
      }
    } finally {
      setSubmitting(false);
      setTotpCode("");
    }
  }

  if (step === "checking") {
    return (
      <div className="page">
        <div className="card">
          <p>Checking registration status...</p>
        </div>
      </div>
    );
  }

  if (step === "already-registered") {
    return (
      <div className="page">
        <div className="card">
          <h1>Admin Already Registered</h1>
          <p className="subtitle">
            This deployment already has a master admin. If that's not you, ask them to create you a sub-admin
            account from their dashboard instead — a second self-registration is intentionally refused so nobody
            can take over an existing deployment.
          </p>
          <Link to="/admin/login">
            <button type="button">Go to Admin Login</button>
          </Link>
        </div>
      </div>
    );
  }

  if (step === "done") {
    return (
      <div className="page">
        <div className="card">
          <h1>Registration Complete</h1>
          <p className="subtitle">Your admin account is set up. Log in with your username, password, and authenticator code.</p>
          <Link to="/admin/login">
            <button type="button">Go to Admin Login</button>
          </Link>
        </div>
      </div>
    );
  }

  if (step === "totp" && setup) {
    return (
      <div className="page">
        <div className="card">
          <h1>Set Up Your Authenticator</h1>
          <p className="subtitle">
            Scan this into Google Authenticator, 1Password, Authy, or similar. Then enter the current code to
            confirm.
          </p>

          <img
            src={`data:image/png;base64,${setup.qr_code_png_base64}`}
            alt="TOTP QR code"
            width={200}
            height={200}
            className="qr-code"
          />

          <p className="subtitle">
            Can't scan it? Enter this manually: <code>{setup.manual_secret}</code>
          </p>

          <form onSubmit={handleTotpSubmit}>
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
            <button type="submit" disabled={submitting || totpCode.length !== 6}>
              {submitting ? "Confirming..." : "Confirm & Finish Setup"}
            </button>
          </form>
        </div>
      </div>
    );
  }

  return (
    <div className="page">
      <div className="card">
        <h1>Register Master Admin Account</h1>
        <p className="subtitle">
          One-time setup for this deployment's first (master) admin. You'll need the setup token from whoever
          configured the server's <code>ADMIN_SETUP_TOKEN</code>. The master admin can create additional sub-admins
          later from their dashboard — no setup token needed for that.
        </p>
        <form onSubmit={handleCredentialsSubmit}>
          <label htmlFor="setupToken">Setup Token</label>
          <input
            id="setupToken"
            type="password"
            autoComplete="off"
            value={setupToken}
            onChange={(e) => setSetupToken(e.target.value)}
            disabled={submitting}
          />

          <label htmlFor="username">Username</label>
          <input
            id="username"
            type="text"
            autoComplete="username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            disabled={submitting}
          />

          <label htmlFor="newPassword">Password</label>
          <input
            id="newPassword"
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
            disabled={
              submitting ||
              setupToken.length === 0 ||
              username.length === 0 ||
              password.length === 0 ||
              confirmPassword.length === 0
            }
          >
            {submitting ? "Continuing..." : "Continue"}
          </button>
        </form>
      </div>
    </div>
  );
}
