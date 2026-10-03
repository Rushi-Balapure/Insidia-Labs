/** Springs from the apple-design skill. Default motion is critically damped. */
export const springs = {
  move: { type: "spring" as const, bounce: 0, duration: 0.4 },
  sheet: { type: "spring" as const, bounce: 0.2, duration: 0.3 },
  press: { type: "spring" as const, bounce: 0, duration: 0.1 },
};

export const typeScale = {
  display: { fontSize: "2.5rem", lineHeight: 1.05, letterSpacing: "-0.02em" },
  title: { fontSize: "1.5rem", lineHeight: 1.15, letterSpacing: "-0.011em" },
  body: { fontSize: "1rem", lineHeight: 1.5, letterSpacing: "0em" },
  caption: { fontSize: "0.8125rem", lineHeight: 1.35, letterSpacing: "0.01em" },
};

export const severity = {
  critical: "#b42318",
  high: "#c2410c",
  medium: "#a16207",
  low: "#3f6212",
  info: "#1d4ed8",
};
