import { useCallback, useEffect, useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import {
  ApiError,
  createSubAdminConfirm,
  createSubAdminStart,
  getMe,
  listAdmins,
  type AdminSummary,
  type RegisterStartResponse,
} from "../api/client";

type FormStep = "closed" | "credentials" | "totp";

const MIN_USERNAME_LENGTH = 3;
const MIN_PASSWORD_LENGTH = 12;

export default function AdminManagement() {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(true);
  const [admins, setAdmins] = useState<AdminSummary[]>([]);
  const [error, setError] = useState<string | null>(null);

  const [formStep, setFormStep] = useState<FormStep>("closed");
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [setup, setSetup] = useState<RegisterStartResponse | null>(null);
  const [totpCode, setTotpCode] = useState("");
  const [successMessage, setSuccessMessage] = useState<string | null>(null);

  const loadAdmins = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await listAdmins();
      setAdmins(data);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        navigate("/admin/login");
        return;
      }
      if (err instanceof ApiError && err.status === 403) {
        setError("Only the master admin can manage other admins.");
        return;
      }
      setError("Failed to load admins.");
    } finally {
      setLoading(false);
    }
  }, [navigate]);

  useEffect(() => {
    getMe()
      .then((me) => {
        if (me.role !== "master") {
          setError("Only the master admin can manage other admins.");
          setLoading(false);
          return;
        }
        loadAdmins();
      })
      .catch((err) => {
        if (err instanceof ApiError && err.status === 401) {
          navigate("/admin/login");
          return;
        }
        setError("Failed to check admin status.");
        setLoading(false);
      });
  }, [loadAdmins, navigate]);

  function openForm() {
    setFormStep("credentials");
    setFormError(null);
    setSuccessMessage(null);
  }

  function closeForm() {
    setFormStep("closed");
    setUsername("");
    setPassword("");
    setConfirmPassword("");
    setSetup(null);
    setTotpCode("");
    setFormError(null);
  }

  async function handleCredentialsSubmit(e: FormEvent) {
    e.preventDefault();
    setFormError(null);

    if (username.length < MIN_USERNAME_LENGTH) {
      setFormError(`Username must be at least ${MIN_USERNAME_LENGTH} characters.`);
      return;
    }
    if (password.length < MIN_PASSWORD_LENGTH) {
      setFormError(`Password must be at least ${MIN_PASSWORD_LENGTH} characters.`);
      return;
    }
    if (password !== confirmPassword) {
      setFormError("Passwords do not match.");
      return;
    }

    setSubmitting(true);
    try {
      const result = await createSubAdminStart(username, password);
      setSetup(result);
      setFormStep("totp");
    } catch (err) {
      if (err instanceof ApiError && err.status === 409) {
        setFormError("That username is already taken.");
      } else {
        setFormError("Something went wrong. Please try again.");
      }
    } finally {
      setSubmitting(false);
      setPassword("");
      setConfirmPassword("");
    }
  }

  async function handleTotpSubmit(e: FormEvent) {
    e.preventDefault();
    if (!setup) return;
    setFormError(null);
    setSubmitting(true);
    try {
      const result = await createSubAdminConfirm(setup.registration_token, totpCode);
      setSuccessMessage(
        `Sub-admin created. Granted access to ${result.containers_granted} existing record(s) submitted before they were created.`,
      );
      closeForm();
      await loadAdmins();
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        setFormError("Wrong code. Try the current one from your authenticator app.");
      } else if (err instanceof ApiError && err.status === 404) {
        setFormError("This registration attempt expired. Please start over.");
        setFormStep("credentials");
        setSetup(null);
      } else {
        setFormError("Something went wrong. Please try again.");
      }
    } finally {
      setSubmitting(false);
      setTotpCode("");
    }
  }

  return (
    <div className="dashboard-page">
      <div className="dashboard-header">
        <h1>Manage Admins</h1>
        <div className="dashboard-actions">
          <Link to="/admin">
            <button type="button">Back to Dashboard</button>
          </Link>
        </div>
      </div>

      {error && <p className="error-text">{error}</p>}
      {successMessage && <p className="subtitle">{successMessage}</p>}

      {!error && (
        <>
          {loading ? (
            <p>Loading...</p>
          ) : (
            <table className="submissions-table">
              <thead>
                <tr>
                  <th>Username</th>
                  <th>Role</th>
                  <th>Status</th>
                  <th>Created</th>
                </tr>
              </thead>
              <tbody>
                {admins.map((a) => (
                  <tr key={a.id}>
                    <td>{a.username}</td>
                    <td>{a.role}</td>
                    <td>{a.status}</td>
                    <td>{new Date(a.created_at).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}

          {formStep === "closed" && (
            <button type="button" style={{ marginTop: "1.5rem" }} onClick={openForm}>
              Create Sub-Admin
            </button>
          )}

          {formStep === "credentials" && (
            <div className="card" style={{ marginTop: "1.5rem", maxWidth: 420 }}>
              <h2 style={{ marginTop: 0, fontSize: "1.1rem" }}>New Sub-Admin</h2>
              <p className="subtitle">
                They'll get full decrypt access, including to records submitted before they existed.
              </p>
              <form onSubmit={handleCredentialsSubmit}>
                <label htmlFor="subUsername">Username</label>
                <input
                  id="subUsername"
                  type="text"
                  autoComplete="off"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  disabled={submitting}
                />

                <label htmlFor="subPassword">Password</label>
                <input
                  id="subPassword"
                  type="password"
                  autoComplete="new-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  disabled={submitting}
                />

                <label htmlFor="subConfirmPassword">Confirm Password</label>
                <input
                  id="subConfirmPassword"
                  type="password"
                  autoComplete="new-password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  disabled={submitting}
                />

                {formError && <p className="error-text">{formError}</p>}

                <div style={{ display: "flex", gap: "0.75rem" }}>
                  <button type="submit" disabled={submitting}>
                    {submitting ? "Continuing..." : "Continue"}
                  </button>
                  <button type="button" onClick={closeForm} disabled={submitting}>
                    Cancel
                  </button>
                </div>
              </form>
            </div>
          )}

          {formStep === "totp" && setup && (
            <div className="card" style={{ marginTop: "1.5rem", maxWidth: 420 }}>
              <h2 style={{ marginTop: 0, fontSize: "1.1rem" }}>Set Up Their Authenticator</h2>
              <p className="subtitle">Have them scan this now, or save the secret to set up later.</p>

              <img
                src={`data:image/png;base64,${setup.qr_code_png_base64}`}
                alt="TOTP QR code"
                width={180}
                height={180}
                className="qr-code"
              />
              <p className="subtitle">
                Manual entry secret: <code>{setup.manual_secret}</code>
              </p>

              <form onSubmit={handleTotpSubmit}>
                <label htmlFor="subTotp">Authenticator Code</label>
                <input
                  id="subTotp"
                  type="text"
                  inputMode="numeric"
                  maxLength={6}
                  autoComplete="one-time-code"
                  placeholder="6-digit code"
                  value={totpCode}
                  onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, ""))}
                  disabled={submitting}
                />
                {formError && <p className="error-text">{formError}</p>}
                <div style={{ display: "flex", gap: "0.75rem" }}>
                  <button type="submit" disabled={submitting || totpCode.length !== 6}>
                    {submitting ? "Confirming..." : "Confirm & Finish"}
                  </button>
                  <button type="button" onClick={closeForm} disabled={submitting}>
                    Cancel
                  </button>
                </div>
              </form>
            </div>
          )}
        </>
      )}
    </div>
  );
}
