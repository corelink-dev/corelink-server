#!/usr/bin/env tsx
/**
 * REAPI reference auto-generator.
 *
 * Walks every `.proto` file under the repo, parses it with `protobufjs`, and
 * emits one MDX page per service into `docs/reference/reapi/_generated/`.
 *
 * The script supports two modes:
 *   - `pnpm docs:gen`        — write the MDX files in place.
 *   - `pnpm docs:gen:check`  — write to a temp dir and diff against the
 *                              committed output. Exit non-zero on drift.
 *
 * Drift prevention is canonical per CTRL-DOC-AUTO-GEN / Quality Standard
 * 14.s18.8 (WI-S18-002 §6.1 item 3).
 */

import { execSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import protobuf from "protobufjs";

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(__dirname, "..", "..", "..");
const GENERATED_DIR = resolve(__dirname, "..", "docs", "reference", "reapi", "_generated");

interface ServiceDoc {
  protoPath: string;
  service: string;
  pkg: string;
  comment: string;
  methods: Array<{ name: string; request: string; response: string; comment: string; streaming: string }>;
  messages: Array<{ name: string; comment: string; fields: Array<{ name: string; type: string; id: number; comment: string }> }>;
}

function findProtoFiles(root: string): string[] {
  const out: string[] = [];
  // NB: do not skip `build` — proto packages legitimately use that directory
  // name (e.g. `crates/corelink-reapi/proto/build/bazel/...`). The Docusaurus
  // build artifact lives under `apps/docs/build` and is excluded via the
  // `.docusaurus` cache + explicit checks below.
  const skip = new Set(["node_modules", "target", ".docusaurus", "_archive", ".git"]);
  function walk(dir: string): void {
    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch {
      return;
    }
    for (const name of entries) {
      if (skip.has(name)) continue;
      const full = join(dir, name);
      let st;
      try {
        st = statSync(full);
      } catch {
        continue;
      }
      if (st.isDirectory()) {
        // Explicit skip for the Docusaurus build output folder which would
        // otherwise be picked up by the generic `build` recursion.
        if (full.endsWith("/apps/docs/build")) continue;
        walk(full);
      } else if (name.endsWith(".proto")) {
        out.push(full);
      }
    }
  }
  walk(root);
  return out.sort();
}

function parseProto(file: string): ServiceDoc[] {
  const root = new protobuf.Root();
  // Resolve siblings only — these protos vendor their own imports.
  root.resolvePath = (origin, target) => {
    const candidates = [
      resolve(dirname(file), target),
      resolve(REPO_ROOT, "crates/corelink-reapi/proto", target),
      resolve(REPO_ROOT, "apps/server/proto", target),
    ];
    for (const c of candidates) {
      if (existsSync(c)) return c;
    }
    // Skip unresolved imports — we only need top-level service/message names.
    return null;
  };

  let parsed;
  try {
    parsed = protobuf.parse(readFileSync(file, "utf8"), root, { keepCase: true });
  } catch (err) {
    console.warn(`[gen-reapi-docs] skipping ${file}: ${(err as Error).message}`);
    return [];
  }

  const services: ServiceDoc[] = [];
  const pkg = parsed.package ?? "";

  function visitNamespace(ns: protobuf.NamespaceBase): void {
    if (!ns.nestedArray) return;
    for (const child of ns.nestedArray) {
      if (child instanceof protobuf.Service) {
        const doc: ServiceDoc = {
          protoPath: relative(REPO_ROOT, file),
          service: child.name,
          pkg,
          comment: (child.comment ?? "").trim(),
          methods: child.methodsArray.map((m) => ({
            name: m.name,
            request: m.requestType,
            response: m.responseType,
            comment: (m.comment ?? "").trim(),
            streaming:
              m.requestStream && m.responseStream
                ? "bidirectional"
                : m.requestStream
                  ? "client-streaming"
                  : m.responseStream
                    ? "server-streaming"
                    : "unary",
          })),
          messages: [],
        };
        // Collect messages from the same namespace.
        for (const sibling of ns.nestedArray) {
          if (sibling instanceof protobuf.Type) {
            doc.messages.push({
              name: sibling.name,
              comment: (sibling.comment ?? "").trim(),
              fields: sibling.fieldsArray.map((f) => ({
                name: f.name,
                type: f.repeated ? `repeated ${f.type}` : f.type,
                id: f.id,
                comment: (f.comment ?? "").trim(),
              })),
            });
          }
        }
        services.push(doc);
      }
      if ((child as protobuf.NamespaceBase).nestedArray) {
        visitNamespace(child as protobuf.NamespaceBase);
      }
    }
  }

  visitNamespace(root);
  return services;
}

/**
 * Escape a type name for a GFM table cell. GFM reads `\\` as an escaped
 * backslash, so a backslash already in the input would consume the `\`
 * inserted before a following `|` and end the cell. Backslashes are
 * therefore escaped first.
 */
export function mdEscape(text: string): string {
  return text
    .replace(/\\/g, "\\\\")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\|/g, "\\|");
}

/** Render untrusted proto comments as literal text in Markdown/MDX. */
export function renderProtoComment(text: string): string {
  return [...text]
    .map((character) => {
      const code = character.charCodeAt(0);
      // Encoding every ASCII punctuation character prevents Markdown syntax,
      // HTML tags, autolinks, and MDX expressions from being interpreted.
      return (code >= 33 && code <= 47) || (code >= 58 && code <= 64) ||
        (code >= 91 && code <= 96) || (code >= 123 && code <= 126)
        ? `&#${code};`
        : character;
    })
    .join("");
}

function renderServiceMdx(svc: ServiceDoc): string {
  const lines: string[] = [];
  lines.push("---");
  lines.push(`id: ${svc.service}`);
  lines.push(`title: ${svc.service} (REAPI v2)`);
  lines.push(`sidebar_label: ${svc.service}`);
  lines.push(`description: Auto-generated reference for the ${svc.service} gRPC service.`);
  lines.push("---");
  lines.push("");
  lines.push(`# ${svc.service}`);
  lines.push("");
  lines.push(`> Auto-generated from \`${svc.protoPath}\`. Do not edit by hand — run \`pnpm docs:gen\`.`);
  lines.push("");
  lines.push(`- Proto package: \`${svc.pkg}\``);
  lines.push(`- Fully-qualified name: \`${svc.pkg}.${svc.service}\``);
  lines.push("");
  if (svc.comment) {
    lines.push("## Overview");
    lines.push("");
    lines.push(renderProtoComment(svc.comment));
    lines.push("");
  }
  lines.push("## Methods");
  lines.push("");
  lines.push("| Method | Request | Response | Streaming |");
  lines.push("| --- | --- | --- | --- |");
  for (const m of svc.methods) {
    lines.push(`| \`${m.name}\` | \`${mdEscape(m.request)}\` | \`${mdEscape(m.response)}\` | ${m.streaming} |`);
  }
  lines.push("");
  for (const m of svc.methods) {
    lines.push(`### ${m.name}`);
    lines.push("");
    lines.push(`- **Request:** \`${m.request}\``);
    lines.push(`- **Response:** \`${m.response}\``);
    lines.push(`- **Streaming:** ${m.streaming}`);
    lines.push("");
    if (m.comment) {
      lines.push(renderProtoComment(m.comment));
      lines.push("");
    }
  }
  if (svc.messages.length > 0) {
    lines.push("## Messages");
    lines.push("");
    for (const msg of svc.messages) {
      lines.push(`### ${msg.name}`);
      lines.push("");
      if (msg.comment) {
        lines.push(renderProtoComment(msg.comment));
        lines.push("");
      }
      if (msg.fields.length > 0) {
        lines.push("| Field | Type | Tag |");
        lines.push("| --- | --- | --- |");
        for (const f of msg.fields) {
          lines.push(`| \`${f.name}\` | \`${mdEscape(f.type)}\` | ${f.id} |`);
        }
        lines.push("");
      }
    }
  }
  lines.push("## Examples");
  lines.push("");
  lines.push(`See manual code examples under [\`_examples/${svc.service}/\`](../_examples/${svc.service}/):`);
  lines.push("");
  lines.push("- Python");
  lines.push("- Go");
  lines.push("- Node / TypeScript");
  lines.push("- CLI (`corelink`)");
  lines.push("");
  return lines.join("\n");
}

function writeFileTracked(target: string, content: string): void {
  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, content);
}

function clearDir(dir: string): void {
  if (existsSync(dir)) rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
}

function generate(outDir: string): ServiceDoc[] {
  clearDir(outDir);
  const protoFiles = findProtoFiles(REPO_ROOT);
  const allServices: ServiceDoc[] = [];
  for (const file of protoFiles) {
    const found = parseProto(file);
    for (const svc of found) {
      allServices.push(svc);
      const target = join(outDir, `${svc.service}.mdx`);
      writeFileTracked(target, renderServiceMdx(svc));
    }
  }
  // Index file.
  const index = [
    "---",
    "id: generated-index",
    "title: REAPI services (auto-generated)",
    "sidebar_label: Services",
    "---",
    "",
    "# REAPI services",
    "",
    "Auto-generated from the vendored `.proto` files. Each service page below is regenerated from source by `pnpm docs:gen`.",
    "",
    ...allServices.map((s) => `- [${s.service}](./${s.service}.mdx) — \`${s.pkg}.${s.service}\` (${s.methods.length} methods)`),
    "",
  ].join("\n");
  writeFileTracked(join(outDir, "index.mdx"), index);
  return allServices;
}

function checkDrift(): number {
  // Generate into a temp shadow dir and diff against the committed output.
  const shadow = join(GENERATED_DIR, "..", "_generated.shadow");
  const services = generate(shadow);
  let drift = false;
  try {
    execSync(`diff -r --brief "${GENERATED_DIR}" "${shadow}"`, { stdio: "pipe" });
  } catch (err) {
    drift = true;
    const out = (err as { stdout?: Buffer }).stdout?.toString() ?? "";
    console.error(out);
  }
  rmSync(shadow, { recursive: true, force: true });
  if (drift) {
    console.error("[gen-reapi-docs] DRIFT detected between .proto files and committed MDX.");
    console.error("[gen-reapi-docs] Run `pnpm docs:gen` and commit the result.");
    return 1;
  }
  console.log(`[gen-reapi-docs] no drift — ${services.length} service(s) up-to-date.`);
  return 0;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const checkMode = process.argv.includes("--check");
  if (checkMode) {
    process.exit(checkDrift());
  } else {
    const services = generate(GENERATED_DIR);
    console.log(`[gen-reapi-docs] wrote ${services.length} service page(s) to ${relative(REPO_ROOT, GENERATED_DIR)}`);
  }
}
