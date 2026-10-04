/** Springs from the apple-design skill. Default motion is critically damped. */
export const springs = {
  move: { type: "spring" as const, bounce: 0, duration: 0.45 },
  pulse: { type: "spring" as const, bounce: 0, duration: 0.35 },
  press: { type: "spring" as const, bounce: 0, duration: 0.1 },
};

export const severity = {
  critical: "#b42318",
  high: "#c2410c",
  medium: "#f6c13f",
  low: "#3f6212",
  info: "#1d4ed8",
};

export const LEAD_COOLDOWN_MS = 30_000;
export const LEAD_MAILBOX = "insidialabs@gmail.com";
