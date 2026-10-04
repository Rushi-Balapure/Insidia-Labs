import { useState, type FormEvent } from "react";
import { mailtoHref, validateLead, type LeadInput } from "../lib/lead";

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
  const [errorField, setErrorField] = useState("");
  const [sent, setSent] = useState(false);

  function update(field: keyof LeadInput, value: string) {
    setValues((current) => ({ ...current, [field]: value }));
  }

  function onSubmit(event: FormEvent<HTMLFormElement>) {
    const last = Number(sessionStorage.getItem(STORAGE_KEY) || "") || null;
    const result = validateLead(values, { endpoint, lastSubmitAt: last, now: Date.now() });
    if (!result.ok) {
      event.preventDefault();
      setErrorField(result.field);
      setMessage(result.message);
      return;
    }
    if (result.channel === "dropped" || result.channel === "mailto") {
      event.preventDefault();
      sessionStorage.setItem(STORAGE_KEY, String(Date.now()));
      setSent(true);
      setMessage(
        result.channel === "mailto"
          ? "Your mail app should open with the request. We only use it to reply about access."
          : "Thanks. If this was a test, nothing was sent.",
      );
      if (result.channel === "mailto") window.location.href = mailtoHref(values);
      return;
    }
    sessionStorage.setItem(STORAGE_KEY, String(Date.now()));
  }

  if (sent) {
    return <p className="muted">{message}</p>;
  }

  return (
    <form className="form" action={endpoint || undefined} method="post" onSubmit={onSubmit} noValidate>
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
      {message ? <p className="field-error">{message}</p> : null}
      <button className="btn" type="submit">
        {values.interest === "design-partner" ? "Apply to be a design partner" : "Join the waitlist"}
      </button>
      <p className="muted" style={{ fontSize: "0.85rem" }}>
        Early access opens in December 2026, starting with three design partners. This form does not create a product account.
      </p>
    </form>
  );
}
