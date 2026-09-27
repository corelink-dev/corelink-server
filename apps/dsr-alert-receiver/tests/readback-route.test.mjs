import { describe, expect, it } from "vitest";
import { readFile } from "node:fs/promises";
import { assertReadbackPath, READBACK_TARGET, ReadbackError, readWorkerInventory, validateReadbackContext } from "../scripts/readback-route.mjs";

const context = {
  repository: READBACK_TARGET.repository,
  ref: "refs/heads/main",
  sha: "a".repeat(40),
  checkoutSha: "a".repeat(40),
  readbackOnly: "true",
  apiToken: "test-token-never-real",
};
const versionId = "123e4567-e89b-42d3-a456-426614174000";
const deploymentId = "123e4567-e89b-42d3-a456-426614174001";

function apiFixture(overrides = {}) {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url: String(url), init });
    const path = new URL(url).pathname.replace(/^\/client\/v4(?=\/)/, "");
    let result;
    if (path.endsWith("/workers/scripts")) result = [{ id: READBACK_TARGET.workerName, routes: [] }];
    else if (path.endsWith("/versions")) result = { items: [{ id: versionId, metadata: { annotations: { "workers/tag": `b216-${"a".repeat(40)}` } } }] };
    else if (path.endsWith("/deployments")) result = { deployments: [{ id: deploymentId, versions: [{ version_id: versionId, percentage: 100 }] }] };
    else if (path.endsWith("/subdomain")) result = { enabled: true, previews_enabled: false };
    else throw new Error("unexpected path");
    const override = overrides[path];
    const payload = override ?? { success: true, result };
    return new Response(JSON.stringify(payload), { status: payload.statusCode ?? 200, headers: { "content-type": "application/json" } });
  };
  return { calls, fetchImpl };
}

describe("B-216 read-only Worker inventory", () => {
  it("keeps workflow readback mode separate from every mutative setup/deploy step", async () => {
    const workflow = await readFile(new URL("../../../.github/workflows/b216-receiver-deploy-nonprod.yml", import.meta.url), "utf8");
    expect(workflow).toContain("readback_only:");
    expect(workflow).toContain("default: false");
    expect(workflow).toContain("type: boolean");
    expect(workflow).toContain("if: ${{ inputs.readback_only }}");
    expect(workflow).toContain("if: ${{ !inputs.readback_only }}");
    const readback = workflow.split("- name: Read fixed Worker inventory without mutation")[1].split("- name: Provision exact receiver target")[0];
    expect(readback).toContain("B216_CF_RECEIVER_WRITE_TOKEN: ${{ secrets.B216_CF_RECEIVER_WRITE_TOKEN }}");
    expect(readback).not.toContain("B216_DSR_ALERT_RECEIVER_TOKEN");
    expect(readback).not.toContain("run-deploy-route.mjs");
  });

  it("reads the exact fixed target using GET only and emits redacted status", async () => {
    const { calls, fetchImpl } = apiFixture();
    const receipt = await readWorkerInventory({ context, fetchImpl, now: () => "2026-09-27T00:00:00.000Z" });
    expect(calls.length).toBe(4);
    for (const { url, init } of calls) {
      expect(init.method).toBe("GET");
      expect(init.body).toBeUndefined();
      expect(url).toContain(`/accounts/${READBACK_TARGET.accountId}/`);
    }
    expect(receipt.worker).toEqual({ exists: true, inventory_count: 1 });
    expect(receipt.routes).toEqual({ status: "known", count: 0 });
    expect(receipt.versions.items[0]).toEqual({ id: versionId, tag: `b216-${"a".repeat(40)}` });
    expect(receipt.deployments.active.versions).toEqual([{ version_id: versionId, percentage: 100 }]);
    expect(receipt.subdomain).toEqual({ status: "known", enabled: true, previews_enabled: false });
  });

  it("refuses wrong repository/ref/SHA/mode/token before any provider request", () => {
    for (const change of [
      { repository: "someone/else" }, { ref: "refs/heads/other" }, { sha: "bad" },
      { checkoutSha: "b".repeat(40) }, { readbackOnly: "false" }, { apiToken: "" },
    ]) {
      expect(() => validateReadbackContext({ ...context, ...change })).toThrow(ReadbackError);
    }
  });

  it("allows only the fixed account and Worker paths", () => {
    expect(assertReadbackPath(`/accounts/${READBACK_TARGET.accountId}/workers/scripts`)).toBe(true);
    expect(assertReadbackPath(`/accounts/${READBACK_TARGET.accountId}/workers/scripts/${READBACK_TARGET.workerName}/versions?page=1&per_page=100`)).toBe(true);
    for (const path of [
      "/accounts/00000000000000000000000000000000/workers/scripts",
      `/accounts/${READBACK_TARGET.accountId}/workers/scripts/other-worker/versions`,
      `/accounts/${READBACK_TARGET.accountId}/workers/scripts/${READBACK_TARGET.workerName}/secrets`,
      `/accounts/${READBACK_TARGET.accountId}/workers/scripts?page=1&per_page=100`,
    ]) expect(() => assertReadbackPath(path)).toThrow(ReadbackError);
  });

  it("rejects duplicate target scripts and malformed provider results", async () => {
    const { fetchImpl } = apiFixture({
      [`/accounts/${READBACK_TARGET.accountId}/workers/scripts`]: { success: true, result: [{ id: READBACK_TARGET.workerName }, { id: READBACK_TARGET.workerName }] },
    });
    await expect(readWorkerInventory({ context, fetchImpl })).rejects.toMatchObject({ code: "worker_duplicate_name" });
    const malformed = apiFixture({
      [`/accounts/${READBACK_TARGET.accountId}/workers/scripts`]: { success: true, result: {} },
    });
    await expect(readWorkerInventory({ context, fetchImpl: malformed.fetchImpl })).rejects.toMatchObject({ code: "worker_inventory_ambiguous" });
  });

  it("reports optional routes as unknown and rejects malformed route shapes", async () => {
    const missing = apiFixture({
      [`/accounts/${READBACK_TARGET.accountId}/workers/scripts`]: { success: true, result: [{ id: READBACK_TARGET.workerName }] },
    });
    const receipt = await readWorkerInventory({ context, fetchImpl: missing.fetchImpl });
    expect(receipt.routes).toEqual({ status: "unknown" });
    const malformed = apiFixture({
      [`/accounts/${READBACK_TARGET.accountId}/workers/scripts`]: { success: true, result: [{ id: READBACK_TARGET.workerName, routes: [{ pattern: "sensitive" }] }] },
    });
    await expect(readWorkerInventory({ context, fetchImpl: malformed.fetchImpl })).rejects.toMatchObject({ code: "worker_routes_ambiguous" });
  });

  it("distinguishes exact absent worker 404 from provider errors", async () => {
    const calls = [];
    const fetchImpl = async (url, init) => {
      calls.push({ url: String(url), init });
      if (new URL(url).pathname.endsWith("/workers/scripts")) return Response.json({ success: true, result: [] });
      return new Response("", { status: 404 });
    };
    const absent = await readWorkerInventory({ context, fetchImpl });
    expect(absent.worker.exists).toBe(false);
    expect(absent.versions.status).toBe("absent");
    expect(absent.inventory_consistency).toBe("worker_absent");
    expect(calls.every(({ init }) => init.method === "GET")).toBe(true);

    const denied = apiFixture({
      [`/accounts/${READBACK_TARGET.accountId}/workers/scripts`]: { success: false, statusCode: 403 },
    });
    await expect(readWorkerInventory({ context, fetchImpl: denied.fetchImpl })).rejects.toMatchObject({ code: "provider_response_rejected" });
  });

  it("fails closed when the script inventory says present but exact versions endpoint is 404", async () => {
    const fetchImpl = async (url) => {
      const path = new URL(url).pathname;
      if (path.endsWith("/workers/scripts")) return Response.json({ success: true, result: [{ id: READBACK_TARGET.workerName }] });
      return new Response("", { status: 404 });
    };
    await expect(readWorkerInventory({ context, fetchImpl })).rejects.toMatchObject({ code: "worker_versions_ambiguous" });
  });

  it("reports versions from an upload that exists before the script-list entry", async () => {
    const calls = [];
    const fetchImpl = async (url, init) => {
      calls.push({ url: String(url), init });
      const path = new URL(url).pathname;
      if (path.endsWith("/workers/scripts")) return Response.json({ success: true, result: [] });
      if (path.endsWith("/versions")) return Response.json({
        success: true,
        result: {
          items: [{ id: versionId, metadata: { annotations: { "workers/tag": `b216-source-${"a".repeat(40)}` } } }],
        },
      });
      if (path.endsWith("/deployments") || path.endsWith("/subdomain")) return new Response("", { status: 404 });
      throw new Error("unexpected path");
    };
    const receipt = await readWorkerInventory({ context, fetchImpl });
    expect(receipt.worker.exists).toBe(false);
    expect(receipt.versions).toEqual({ status: "known", count: 1, items: [{ id: versionId, tag: `b216-source-${"a".repeat(40)}` }] });
    expect(receipt.deployments).toEqual({ status: "absent" });
    expect(receipt.subdomain).toEqual({ status: "absent" });
    expect(receipt.inventory_consistency).toBe("partial_version_only");
    expect(calls.every(({ init }) => init.method === "GET")).toBe(true);
  });

  it("marks script absence plus an active deployment as inconsistent", async () => {
    const fetchImpl = async (url) => {
      const path = new URL(url).pathname;
      if (path.endsWith("/workers/scripts")) return Response.json({ success: true, result: [] });
      if (path.endsWith("/versions")) return Response.json({ success: true, result: { items: [] } });
      if (path.endsWith("/deployments")) return Response.json({ success: true, result: { deployments: [{ id: deploymentId, versions: [{ version_id: versionId, percentage: 100 }] }] } });
      if (path.endsWith("/subdomain")) return new Response("", { status: 404 });
      throw new Error("unexpected path");
    };
    const receipt = await readWorkerInventory({ context, fetchImpl });
    expect(receipt.inventory_consistency).toBe("inconsistent_provider_inventory");
  });

  it("rejects version/deployment/subdomain ambiguity without leaking response data", async () => {
    const badVersion = apiFixture({
      [`/accounts/${READBACK_TARGET.accountId}/workers/scripts/${READBACK_TARGET.workerName}/versions`]: {
        success: true,
        result: { items: [{ id: "not-a-uuid", metadata: { annotations: { "workers/tag": "private" } } }] },
      },
    });
    await expect(readWorkerInventory({ context, fetchImpl: badVersion.fetchImpl })).rejects.toMatchObject({ code: "worker_versions_ambiguous" });
    const badDeployment = apiFixture({
      [`/accounts/${READBACK_TARGET.accountId}/workers/scripts/${READBACK_TARGET.workerName}/deployments`]: { success: true, result: { deployments: [{ id: "bad", versions: [] }] } },
    });
    await expect(readWorkerInventory({ context, fetchImpl: badDeployment.fetchImpl })).rejects.toMatchObject({ code: "worker_deployments_ambiguous" });
    const badSubdomain = apiFixture({
      [`/accounts/${READBACK_TARGET.accountId}/workers/scripts/${READBACK_TARGET.workerName}/subdomain`]: { success: true, result: { enabled: "yes", previews_enabled: false } },
    });
    await expect(readWorkerInventory({ context, fetchImpl: badSubdomain.fetchImpl })).rejects.toMatchObject({ code: "worker_subdomain_ambiguous" });
  });

  it("never serializes route patterns, response bodies, or request URLs into a receipt", async () => {
    const { fetchImpl } = apiFixture({
      [`/accounts/${READBACK_TARGET.accountId}/workers/scripts`]: {
        success: true,
        result: [{ id: READBACK_TARGET.workerName, routes: [{ id: "route-id", pattern: "secret.example/*", script: READBACK_TARGET.workerName }] }],
      },
    });
    const receipt = await readWorkerInventory({ context, fetchImpl });
    const serialized = JSON.stringify(receipt);
    expect(serialized).not.toContain("secret.example");
    expect(serialized).not.toContain("route-id");
    expect(serialized).not.toContain("test-token-never-real");
  });
});
