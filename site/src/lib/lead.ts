import { LEAD_COOLDOWN_MS, LEAD_MAILBOX } from "../design/tokens";

const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export type LeadInput = {
  email: string;
  company: string;
  role: string;
  interest: string;
  aiSurface: string;
  honeypot: string;
};

export type LeadResult =
  | { ok: true; channel: "hosted-form" | "mailto" | "dropped" }
  | { ok: false; field: "email" | "company" | "rate"; message: string };

export function validateLead(
  input: LeadInput,
  opts: { endpoint: string; lastSubmitAt: number | null; now: number },
): LeadResult {
  if (input.honeypot.trim() !== "") return { ok: true, channel: "dropped" };
  if (opts.lastSubmitAt != null && opts.now - opts.lastSubmitAt < LEAD_COOLDOWN_MS) {
    return { ok: false, field: "rate", message: "Please wait a moment before sending again." };
  }
  if (!EMAIL.test(input.email.trim())) {
    return { ok: false, field: "email", message: "Enter a work email address." };
  }
  if (input.company.trim().length < 2) {
    return { ok: false, field: "company", message: "Enter your company." };
  }
  return { ok: true, channel: opts.endpoint.trim() ? "hosted-form" : "mailto" };
}

export const MAILTO_NOTICE = "Your mail app opened with this request. The form still has what you typed.";

export function acknowledged(status: number): boolean {
  return status >= 200 && status < 300;
}

export function mailtoHref(input: LeadInput): string {
  const subject = input.interest === "design-partner" ? "Design partner application" : "Waitlist";
  const body = [
    `Email: ${input.email.trim()}`,
    `Company: ${input.company.trim()}`,
    `Role: ${input.role.trim() || "(not given)"}`,
    `Interest: ${input.interest === "design-partner" ? "Design partner" : "Waitlist"}`,
    `What the AI touches: ${input.aiSurface.trim() || "(not given)"}`,
  ].join("\n");
  return `mailto:${LEAD_MAILBOX}?subject=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
}
