import { describe, expect, it } from "vitest";
import { humanizeCategory } from "./format";

describe("humanizeCategory", () => {
  it("formats score categories for the dashboard", () => {
    expect(humanizeCategory("code_quality")).toBe("Code Quality");
  });
});
