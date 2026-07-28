import { useEffect, useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ApiError, getUserMe, submitAadhaar, userLogout, type UserMeResponse } from "../api/client";

const AADHAAR_PATTERN = /^\d{12}$/;

type Status = "idle" | "submitting" | "success" | "error";

export default function SubmitAadhaar() {
  const navigate = useNavigate();
  const [checkingAuth, setCheckingAuth] = useState(true);
  const [me, setMe] = useState<UserMeResponse | null>(null);
  const [value, setValue] = useState("");
  const [status, setStatus] = useState<Status>("idle");
  const [message, setMessage] = useState("");
  const [referenceId, setReferenceId] = useState<string | null>(null);
  const [maskedPreview, setMaskedPreview] = useState<string | null>(null);

  useEffect(() => {
    getUserMe()
      .then((response) => {
        setMe(response);
        setCheckingAuth(false);
      })
      .catch(() => {
        navigate("/login");
      });
  }, [navigate]);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!AADHAAR_PATTERN.test(value)) {
      setStatus("error");
      setMessage("Enter exactly 12 digits.");
      return;
    }

    setStatus("submitting");
    setMessage("");
    try {
      const result = await submitAadhaar(value);
      setReferenceId(result.reference_id);
      setMaskedPreview(result.masked_preview);
      setStatus("success");
      setValue(""); // never keep the plaintext number around after submit
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        navigate("/login");
        return;
      }
      setStatus("error");
      setMessage(
        err instanceof ApiError
          ? err.status === 400
            ? "That doesn't look like a valid Aadhaar number."
            : "Something went wrong. Please try again."
          : "Could not reach the server. Please try again.",
      );
    }
  }

  function handleReset() {
    setStatus("idle");
    setReferenceId(null);
    setMaskedPreview(null);
    setMessage("");
  }

  async function handleLogout() {
    try {
      await userLogout();
    } finally {
      navigate("/login");
    }
  }

  if (checkingAuth) {
    return (
      <div className="page">
        <div className="card">
          <p>Checking login status...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="page">
      <div className="card">
        <h1>Submit Aadhaar Number</h1>
        {me && (
          <p className="subtitle" style={{ marginBottom: "0.5rem" }}>
            Logged in as <strong>{me.username}</strong> — <Link to="/my-submissions">My Submissions</Link> ·{" "}
            <a href="#" onClick={(e) => { e.preventDefault(); handleLogout(); }}>Log Out</a>
          </p>
        )}
        <p className="subtitle">
          Your number is encrypted before it is ever written to the database. Only an
          authenticated admin, using their password and authenticator code, can decrypt it.
        </p>

        {status === "success" ? (
          <div className="success-box">
            <p>Submitted successfully.</p>
            <p className="reference">
              Aadhaar Number: <code>{maskedPreview}</code>
            </p>
            <p className="reference">
              Reference ID: <code>{referenceId}</code>
            </p>
            <button onClick={handleReset}>Submit another</button>
          </div>
        ) : (
          <form onSubmit={handleSubmit}>
            <label htmlFor="aadhaar">Aadhaar Number</label>
            <input
              id="aadhaar"
              type="text"
              inputMode="numeric"
              maxLength={12}
              autoComplete="off"
              placeholder="12-digit number"
              value={value}
              onChange={(e) => setValue(e.target.value.replace(/\D/g, ""))}
              disabled={status === "submitting"}
            />
            {status === "error" && <p className="error-text">{message}</p>}
            <button type="submit" disabled={status === "submitting" || value.length !== 12}>
              {status === "submitting" ? "Submitting..." : "Submit"}
            </button>
          </form>
        )}
      </div>
    </div>
  );
}
