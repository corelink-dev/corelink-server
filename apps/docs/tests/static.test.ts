import fs from "node:fs";
import path from "node:path";
import { describe, expect, it } from "vitest";
import { renderProtoComment } from "../scripts/gen-reapi-docs";

const STATIC_DIR = path.resolve(__dirname, "..", "static");
const SITEMAP_LINE = "Sitemap: https://humangr.com/corelink/docs/sitemap.xml";

function isCanonicalSitemapLine(line: string): boolean {
  return /^Sitemap:[ \t]*https:\/\/humangr\.com\/corelink\/docs\/sitemap\.xml[ \t]*$/.test(line);
}

describe("static/ assets", () => {
  // No CNAME: the docs are served by a Worker (Static Assets) mounted at the
  // canonical path humangr.com/corelink/docs, not a Pages custom domain.

  it("ships a robots.txt that allows crawling and points at the sitemap", () => {
    const robots = fs.readFileSync(
      path.join(STATIC_DIR, "robots.txt"),
      "utf8",
    );
    expect(robots).toMatch(/User-agent:\s*\*/);
    expect(robots).toMatch(/Allow:\s*\//);
    expect(robots.split(/\r?\n/).filter(isCanonicalSitemapLine)).toContain(SITEMAP_LINE);
  });

  it("requires the sitemap directive to occupy an exact canonical line", () => {
    expect(isCanonicalSitemapLine(SITEMAP_LINE)).toBe(true);
    expect(isCanonicalSitemapLine(`# ${SITEMAP_LINE}`)).toBe(false);
    expect(isCanonicalSitemapLine(`${SITEMAP_LINE} evil`)).toBe(false);
    expect(isCanonicalSitemapLine("Sitemap: https://humangr.com/sitemap.xml")).toBe(false);
  });

  it("renders proto comments as inert literal text", () => {
    const rendered = renderProtoComment(
      '<script>alert(1)</script> {globalThis.pwned} [click](javascript:alert(1))\n# heading\n- item',
    );

    expect(rendered).not.toMatch(/<script|\{globalThis|\]\(|^# |^- /m);
    expect(rendered).toContain("&#60;script&#62;");
    expect(rendered).toContain("&#123;globalThis&#46;pwned&#125;");
    expect(rendered).toContain("&#91;click&#93;");
  });

  it("ships favicon and logo SVGs referenced by docusaurus.config.ts", () => {
    expect(fs.existsSync(path.join(STATIC_DIR, "img", "favicon.svg"))).toBe(
      true,
    );
    expect(fs.existsSync(path.join(STATIC_DIR, "img", "logo.svg"))).toBe(
      true,
    );
  });
});
