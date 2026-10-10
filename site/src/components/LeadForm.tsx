import { useState, type FormEvent } from "react";
import { acknowledged, MAILTO_NOTICE, mailtoHref, validateLead, type LeadInput } from "../lib/lead";

const STORAGE_KEY = "insidia-lead-at";

const empty: LeadInput = {
  email: "",
  company: "",
  role: "",
  interest: "waitlist",
  aiSurface: "",
  honeypot: "",
};

export default function LeadForm({ endpoint = "" }: { endpoint?: string }) {
  const [values, setValues] = useState<LeadInput>(empty);
  const [message, setMessage] = useState("");
  const [status, setStatus] = useState("");
  const [errorField, setErrorField] = useState("");
  const [sent, setSent] = useState(false);
  const [pending, setPending] = useState(false);

  function update(field: keyof LeadInput, value: string) {
    setValues((current) => ({ ...current, [field]: value }));
  }

  async function onSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setMessage("");
    setStatus("");
    const last = Number(sessionStorage.getItem(STORAGE_KEY) || "") || null;
    const result = validateLead(values, { endpoint, lastSubmitAt: last, now: Date.now() });
    if (!result.ok) {
      setErrorField(result.field);
      setMessage(result.message);
      return;
    }
    setErrorField("");
    if (result.channel === "dropped") {
      sessionStorage.setItem(STORAGE_KEY, String(Date.now()));
      setSent(true);
      setStatus("Nothing was sent.");
      return;
    }
    if (result.channel === "mailto") {
      sessionStorage.setItem(STORAGE_KEY, String(Date.now()));
      setStatus(MAILTO_NOTICE);
      window.location.href = mailtoHref(values);
      return;
    }
    setPending(true);
    try {
      const body = new FormData(event.currentTarget);
      const response = await fetch(endpoint, { method: "POST", body, headers: { Accept: "application/json" } });
      if (!acknowledged(response.status)) {
        setMessage("That did not go through. Your answers are still here.");
        return;
      }
      sessionStorage.setItem(STORAGE_KEY, String(Date.now()));
      setSent(true);
      setStatus("Request received. We'll use it only to reply about access.");
    } catch {
      setMessage("That did not go through. Your answers are still here.");
    } finally {
      setPending(false);
    }
  }

  if (sent) {
    return (
      <p className="muted" role="status">
        {status}
      </p>
    );
  }

  return (
    <form className="form" method="post" onSubmit={onSubmit} noValidate aria-busy={pending}>
      <div className="form-row">
        <label>
          Work email
          <input
            name="email"
            type="email"
            autoComplete="email"
            required
            value={values.email}
            onChange={(event) => update("email", event.target.value)}
            aria-invalid={errorField === "email"}
            aria-describedby={errorField === "email" ? "lead-error" : undefined}
          />
        </label>
        <label>
          Company
          <input
            name="company"
            autoComplete="organization"
            required
            value={values.company}
            onChange={(event) => update("company", event.target.value)}
            aria-invalid={errorField === "company"}
            aria-describedby={errorField === "company" ? "lead-error" : undefined}
          />
        </label>
      </div>
      <div className="form-row">
        <label>
          Role
          <input name="role" autoComplete="organization-title" value={values.role} onChange={(event) => update("role", event.target.value)} />
        </label>
        <label>
          Interest
          <select name="interest" value={values.interest} onChange={(event) => update("interest", event.target.value)}>
            <option value="waitlist">Join the waitlist</option>
            <option value="design-partner">Apply to be a design partner</option>
          </select>
        </label>
      </div>
      <label>
        What does your AI touch?
        <textarea name="ai_surface" rows={3} value={values.aiSurface} onChange={(event) => update("aiSurface", event.target.value)} />
      </label>
      <label className="honeypot" aria-hidden="true">
        Company website
        <input
          name="company_website"
          tabIndex={-1}
          autoComplete="off"
          value={values.honeypot}
          onChange={(event) => update("honeypot", event.target.value)}
        />
      </label>
      <p id="lead-error" className="field-error" aria-live="assertive">
        {message}
      </p>
      <p className="muted lead-status" role="status">
        {status}
      </p>
      <button className="btn" type="submit" disabled={pending}>
        {pending ? "Sending" : values.interest === "design-partner" ? "Apply to be a design partner" : "Join the waitlist"}
      </button>
      <p className="muted" style={{ fontSize: "0.85rem" }}>
        Early access opens in December 2026, starting with three design partners. This form does not create a product account.
      </p>
    </form>
  );
}
