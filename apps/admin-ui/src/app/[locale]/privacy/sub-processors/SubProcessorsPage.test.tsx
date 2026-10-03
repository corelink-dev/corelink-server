import { describe, it, expect } from "vitest";
import userEvent from "@testing-library/user-event";
import { renderWithProviders, screen } from "@/test-utils/render";
import { axe } from "@/test-utils/axe";
import { SubProcessorsPage, toCsv } from "./SubProcessorsPage";

const items = [
  {
    id: "cloudflare",
    name: "Cloudflare, Inc.",
    role: "CDN",
    region: "Global",
    certifications: ["ISO 27001", "SOC 2"],
    terms_url: "https://www.cloudflare.com/terms/",
    dpa_url: "https://www.cloudflare.com/cloudflare-customer-dpa/",
  },
  {
    id: "clerk",
    name: "Clerk, Inc.",
    role: "IdP",
    region: "US",
    certifications: ["SOC 2"],
    terms_url: "https://clerk.com/legal/standard-terms",
    dpa_url: "https://clerk.com/legal/dpa",
  },
];

describe("SubProcessorsPage", () => {
  it("renders table with sub-processors", () => {
    renderWithProviders(<SubProcessorsPage locale="en" version="2026-05-14" items={items} />);
    expect(screen.getByRole("table", { name: "Sub-processors" })).toBeInTheDocument();
    expect(screen.getByText("Cloudflare, Inc.")).toBeInTheDocument();
  });

  it("links each vendor's own terms and DPA", () => {
    renderWithProviders(<SubProcessorsPage locale="en" version="2026-05-14" items={items} />);
    for (const item of items) {
      const terms = screen.getByRole("link", { name: `Vendor terms — ${item.name}` });
      const dpa = screen.getByRole("link", { name: `Vendor DPA — ${item.name}` });
      expect(terms).toHaveAttribute("href", item.terms_url);
      expect(dpa).toHaveAttribute("href", item.dpa_url);
      expect(terms).toHaveAttribute("rel", "noopener noreferrer");
    }
  });

  it("shows no acceptance or audit dates", () => {
    renderWithProviders(<SubProcessorsPage locale="en" version="2026-05-14" items={items} />);
    expect(screen.queryByText(/last audit/i)).not.toBeInTheDocument();
  });

  it("table headers are keyboard-reachable via tab", async () => {
    renderWithProviders(<SubProcessorsPage locale="en" version="2026-05-14" items={items} />);
    const sortBtns = screen
      .getAllByRole("button")
      .filter((b) => b.textContent?.toLowerCase().includes("name") || b.textContent?.toLowerCase().includes("region"));
    expect(sortBtns.length).toBeGreaterThan(0);
    const firstBtn = sortBtns[0];
    if (!firstBtn) throw new Error("unreachable: no sort buttons matched");
    firstBtn.focus();
    expect(firstBtn).toHaveFocus();
    await userEvent.tab();
    // Some other focusable element should now have focus.
    expect(document.activeElement).not.toBe(firstBtn);
  });

  it("produces valid CSV", () => {
    const csv = toCsv(items);
    expect(csv.split("\n")).toHaveLength(3);
    expect(csv).toContain("Cloudflare, Inc.");
    expect(csv.split("\n")[0]).toBe("id,name,role,region,certifications,terms_url,dpa_url");
    expect(csv).toContain("https://clerk.com/legal/dpa");
  });

  it("has no a11y violations", async () => {
    const { container } = renderWithProviders(
      <SubProcessorsPage locale="en" version="2026-05-14" items={items} />
    );
    expect(await axe(container)).toHaveNoViolations();
  });
});
