import { describe, expect, it } from "vitest";
import { springs, typeScale } from "./tokens";

describe("design tokens", () => {
  it("uses a critically damped default spring", () => {
    expect(springs.move.bounce).toBe(0);
    expect(springs.move.duration).toBe(0.4);
  });

  it("tightens tracking as type gets larger", () => {
    expect(typeScale.display.letterSpacing < typeScale.body.letterSpacing).toBe(true);
  });
});
