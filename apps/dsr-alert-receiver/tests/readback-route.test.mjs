import { describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { assertReadbackPath, assertTokenDiagnosticPath, READBACK_TARGET, ReadbackError, readTokenPolicyDiagnostic, readWorkerInventory, tokenVerifies, validateReadbackContext, writeReadbackReceipt } from "../scripts/readback-route.mjs";

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
const notAttempted = { http_status: null, error_class: "not_attempted" };
const userOk = { http_status: 200, error_class: "none" };
const activeVerification = { http_status: 200, error_class: "none", active_status: "active", token_id_shape: "valid_32_hex", token_kind: "user", user_verify: userOk, account_verify: notAttempted };
const inactiveVerification = { http_status: 200, error_class: "none", active_status: "inactive", token_id_shape: "valid_32_hex", token_kind: "user", user_verify: userOk, account_verify: notAttempted };
const userVerifyPath = "/client/v4/user/tokens/verify";
const accountTokensPath = `/client/v4/accounts/${READBACK_TARGET.accountId}/tokens`;
const accountVerifyPath = `${accountTokensPath}/verify`;
const targetAccountResource = `com.cloudflare.api.account.${READBACK_TARGET.accountId}`;

// Routes token-diagnostic paths only. The diagnostic swallows a thrown fetch as
// a transport error, so every test using this fixture also asserts the exact
// ordered path list: an unexpected endpoint cannot pass silently.
function tokenFixture(routes) {
  const calls = [];
  const fetchImpl = async (url, init) => {
    calls.push({ url: String(url), init });
    const path = new URL(url).pathname;
    if (!Object.hasOwn(routes, path)) throw new Error("unexpected token path");
    return routes[path]();
  };
  return { calls, fetchImpl, paths: () => calls.map(({ url }) => new URL(url).pathname) };
}

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
    expect(workflow).toContain("if: ${{ inputs.deploy_once }}");
    const readback = workflow.split("- name: Read fixed Worker inventory without mutation")[1].split("- name: Deploy exact receiver target")[0];
    expect(readback).toContain("B216_CF_RECEIVER_WRITE_TOKEN: ${{ secrets.CF_API_TOKEN }}");
    expect(readback).not.toContain("B216_DSR_ALERT_RECEIVER_TOKEN");
    expect(readback).not.toContain("run-deploy-route.mjs");
  });

  it("runs the token diagnostic only through the existing protected readback operator", async () => {
    const workflow = await readFile(new URL("../../../.github/workflows/b216-receiver-deploy-nonprod.yml", import.meta.url), "utf8");
    const runner = await readFile(new URL("../scripts/run-readback-route.mjs", import.meta.url), "utf8");
    expect(workflow).toContain("if: ${{ inputs.readback_only }}");
    const readback = workflow.split("- name: Read fixed Worker inventory without mutation")[1].split("- name: Deploy exact receiver target")[0];
    expect(readback).toContain("B216_CF_RECEIVER_WRITE_TOKEN: ${{ secrets.CF_API_TOKEN }}");
    expect(readback).not.toContain("B216_DSR_ALERT_RECEIVER_TOKEN");
    expect(runner).toContain("includeTokenPolicyDiagnostic: true");
  });

  it("reads token identity then policy once each and emits only fixed exact-account booleans", async () => {
    const calls = [];
    const tokenId = "a".repeat(32);
    const apiToken = "test-token-never-real";
    const fetchImpl = async (url, init) => {
      calls.push({ url: String(url), init });
      const path = new URL(url).pathname;
      const result = path.endsWith("/verify")
        ? { id: tokenId, status: "active" }
        : { policies: [{
          effect: "allow",
          permission_groups: [{ name: "Workers Admin" }],
          resources: { [`com.cloudflare.api.account.${READBACK_TARGET.accountId}`]: "*" },
        }] };
      return Response.json({ success: true, result });
    };
    const diagnostic = await readTokenPolicyDiagnostic({ apiToken, fetchImpl });
    expect(diagnostic).toEqual({
      status: "details_read",
      token_active: true,
      target_account_scope: true,
      workers_admin_on_target_account: true,
      verification: activeVerification,
    });
    expect(calls.map(({ url }) => new URL(url).pathname)).toEqual([
      "/client/v4/user/tokens/verify",
      `/client/v4/user/tokens/${tokenId}`,
    ]);
    for (const { init } of calls) {
      expect(init.method).toBe("GET");
      expect(init.redirect).toBe("error");
      expect(init.signal).toBeInstanceOf(AbortSignal);
      expect(init.headers.authorization).toBe(`Bearer ${apiToken}`);
    }
    expect(JSON.stringify(diagnostic)).not.toContain(apiToken);
    expect(JSON.stringify(diagnostic)).not.toContain(tokenId);
  });

  it("records only an allowlisted active-status and ID-shape summary for malformed verification fields", async () => {
    const tokenId = "f".repeat(32);
    const diagnostic = await readTokenPolicyDiagnostic({
      apiToken: context.apiToken,
      fetchImpl: async () => Response.json({ success: true, result: { id: tokenId, status: { private: "status" } } }),
    });
    expect(diagnostic).toEqual({
      status: "verify_unknown",
      token_active: null,
      target_account_scope: null,
      workers_admin_on_target_account: null,
      verification: { http_status: 200, error_class: "malformed_verification_fields", active_status: "other", token_id_shape: "valid_32_hex", token_kind: "user", user_verify: userOk, account_verify: notAttempted },
    });
    expect(JSON.stringify(diagnostic)).not.toContain(tokenId);
    expect(JSON.stringify(diagnostic)).not.toContain("private");
  });

  it("records a malformed ID shape without retaining its value", async () => {
    const secretLikeId = "provider-private-id-value";
    const diagnostic = await readTokenPolicyDiagnostic({
      apiToken: context.apiToken,
      fetchImpl: async () => Response.json({ success: true, result: { id: secretLikeId, status: "active" } }),
    });
    expect(diagnostic.verification).toEqual({
      http_status: 200,
      error_class: "malformed_verification_fields",
      active_status: "active",
      token_id_shape: "malformed",
      token_kind: "user",
      user_verify: userOk,
      account_verify: notAttempted,
    });
    expect(JSON.stringify(diagnostic)).not.toContain(secretLikeId);
  });

  it("records an HTTP error class and numeric status without reading a non-200 body", async () => {
    const privateBody = "private provider response must not persist";
    const calls = [];
    const diagnostic = await readTokenPolicyDiagnostic({
      apiToken: context.apiToken,
      fetchImpl: async (url) => { calls.push(String(url)); return new Response(privateBody, { status: 502 }); },
    });
    expect(diagnostic).toEqual({
      status: "verify_unknown",
      token_active: null,
      target_account_scope: null,
      workers_admin_on_target_account: null,
      verification: {
        http_status: 502,
        error_class: "http_response",
        active_status: "unknown",
        token_id_shape: "not_checked",
        token_kind: "unknown",
        user_verify: { http_status: 502, error_class: "http_response" },
        account_verify: notAttempted,
      },
    });
    expect(calls).toHaveLength(1);
    expect(JSON.stringify(diagnostic)).not.toContain(privateBody);
  });

  it("tries the account endpoint only after a user 401 or 403, never after other statuses", async () => {
    for (const status of [400, 404, 429, 500, 503]) {
      const { fetchImpl, paths } = tokenFixture({ [userVerifyPath]: () => new Response("private", { status }) });
      const diagnostic = await readTokenPolicyDiagnostic({ apiToken: context.apiToken, fetchImpl });
      expect(paths()).toEqual([userVerifyPath]);
      expect(diagnostic.status).toBe("verify_unknown");
      expect(diagnostic.verification.token_kind).toBe("unknown");
      expect(diagnostic.verification.account_verify).toEqual(notAttempted);
    }
  });

  it("distinguishes a verify 403 on both endpoints by status while keeping response data private", async () => {
    const { fetchImpl, paths } = tokenFixture({
      [userVerifyPath]: () => new Response("private access details", { status: 403 }),
      [accountVerifyPath]: () => new Response("private account access details", { status: 403 }),
    });
    const diagnostic = await readTokenPolicyDiagnostic({ apiToken: context.apiToken, fetchImpl });
    expect(paths()).toEqual([userVerifyPath, accountVerifyPath]);
    expect(diagnostic.status).toBe("unknown_access");
    expect(diagnostic.verification).toEqual({
      http_status: 403,
      error_class: "http_response",
      active_status: "unknown",
      token_id_shape: "not_checked",
      token_kind: "unknown",
      user_verify: { http_status: 403, error_class: "http_response" },
      account_verify: { http_status: 403, error_class: "http_response" },
    });
    expect(JSON.stringify(diagnostic)).not.toContain("private access details");
    expect(JSON.stringify(diagnostic)).not.toContain("private account access details");
  });

  it("keeps a 403 from either endpoint as unknown_access when neither verifies", async () => {
    for (const [userStatus, accountStatus] of [[401, 403], [403, 401]]) {
      const { fetchImpl, paths } = tokenFixture({
        [userVerifyPath]: () => new Response("private", { status: userStatus }),
        [accountVerifyPath]: () => new Response("private", { status: accountStatus }),
      });
      const diagnostic = await readTokenPolicyDiagnostic({ apiToken: context.apiToken, fetchImpl });
      expect(paths()).toEqual([userVerifyPath, accountVerifyPath]);
      expect(diagnostic.status).toBe("unknown_access");
      expect(diagnostic.token_active).toBeNull();
      expect(diagnostic.verification.user_verify).toEqual({ http_status: userStatus, error_class: "http_response" });
      expect(diagnostic.verification.account_verify).toEqual({ http_status: accountStatus, error_class: "http_response" });
    }
  });

  it("records a timeout without retaining an exception message", async () => {
    const calls = [];
    const diagnostic = await readTokenPolicyDiagnostic({
      apiToken: context.apiToken,
      fetchImpl: async (url) => { calls.push(String(url)); throw new DOMException("private timeout text", "TimeoutError"); },
    });
    expect(diagnostic.verification).toEqual({
      http_status: null,
      error_class: "timeout",
      active_status: "unknown",
      token_id_shape: "not_checked",
      token_kind: "unknown",
      user_verify: { http_status: null, error_class: "timeout" },
      account_verify: notAttempted,
    });
    expect(calls).toHaveLength(1);
    expect(JSON.stringify(diagnostic)).not.toContain("private timeout text");
  });

  it("records a transport error class without retaining an exception message", async () => {
    const diagnostic = await readTokenPolicyDiagnostic({
      apiToken: context.apiToken,
      fetchImpl: async () => { throw new Error("private transport detail"); },
    });
    expect(diagnostic.verification).toEqual({
      http_status: null,
      error_class: "transport_error",
      active_status: "unknown",
      token_id_shape: "not_checked",
      token_kind: "unknown",
      user_verify: { http_status: null, error_class: "transport_error" },
      account_verify: notAttempted,
    });
    expect(JSON.stringify(diagnostic)).not.toContain("private transport detail");
  });

  it("classifies malformed JSON without retaining its body", async () => {
    const privateBody = "private malformed JSON body";
    const diagnostic = await readTokenPolicyDiagnostic({
      apiToken: context.apiToken,
      fetchImpl: async () => new Response(privateBody, { status: 200 }),
    });
    expect(diagnostic.verification).toEqual({
      http_status: 200,
      error_class: "malformed_json",
      active_status: "unknown",
      token_id_shape: "not_checked",
      token_kind: "unknown",
      user_verify: { http_status: 200, error_class: "malformed_json" },
      account_verify: notAttempted,
    });
    expect(JSON.stringify(diagnostic)).not.toContain(privateBody);
  });

  it("classifies an unsuccessful 200 envelope without retaining provider data", async () => {
    const privateMarker = "private provider error marker";
    const diagnostic = await readTokenPolicyDiagnostic({
      apiToken: context.apiToken,
      fetchImpl: async () => Response.json({ success: false, errors: [{ message: privateMarker }] }),
    });
    expect(diagnostic.verification).toEqual({
      http_status: 200,
      error_class: "malformed_payload",
      active_status: "unknown",
      token_id_shape: "not_checked",
      token_kind: "unknown",
      user_verify: { http_status: 200, error_class: "malformed_payload" },
      account_verify: notAttempted,
    });
    expect(JSON.stringify(diagnostic)).not.toContain(privateMarker);
  });

  it("verifies an account-owned token at the fixed account after a user 401 and reads its account policy", async () => {
    const tokenId = "9".repeat(32);
    const apiToken = "test-account-token-never-real";
    const { calls, fetchImpl, paths } = tokenFixture({
      [userVerifyPath]: () => new Response("private user verify body", { status: 401 }),
      [accountVerifyPath]: () => Response.json({ success: true, result: { id: tokenId, status: "active", expires_on: "2027-01-01T00:00:00Z" } }),
      [`${accountTokensPath}/${tokenId}`]: () => Response.json({
        success: true,
        result: {
          id: tokenId,
          name: "private account token name",
          status: "active",
          policies: [{
            id: "f267e341f3dd4697bd3b9f71dd96247f",
            effect: "allow",
            permission_groups: [{ id: "c8fed203ed3043cba015a93ad1616f1f", name: "Workers Admin", meta: { key: "key", value: "value" } }],
            resources: { [targetAccountResource]: "*" },
          }],
        },
      }),
    });
    const diagnostic = await readTokenPolicyDiagnostic({ apiToken, fetchImpl });
    expect(diagnostic).toEqual({
      status: "details_read",
      token_active: true,
      target_account_scope: true,
      workers_admin_on_target_account: true,
      verification: {
        http_status: 200,
        error_class: "none",
        active_status: "active",
        token_id_shape: "valid_32_hex",
        token_kind: "account",
        user_verify: { http_status: 401, error_class: "http_response" },
        account_verify: { http_status: 200, error_class: "none" },
      },
    });
    expect(paths()).toEqual([userVerifyPath, accountVerifyPath, `${accountTokensPath}/${tokenId}`]);
    for (const { init } of calls) {
      expect(init.method).toBe("GET");
      expect(init.redirect).toBe("error");
      expect(init.signal).toBeInstanceOf(AbortSignal);
      expect(init.headers.authorization).toBe(`Bearer ${apiToken}`);
    }
    const serialized = JSON.stringify(diagnostic);
    expect(serialized).not.toContain(apiToken);
    expect(serialized).not.toContain(tokenId);
    expect(serialized).not.toContain("private user verify body");
    expect(serialized).not.toContain("private account token name");
  });

  it("falls back to the account endpoint after a user 403 as well", async () => {
    const tokenId = "8".repeat(32);
    const { fetchImpl, paths } = tokenFixture({
      [userVerifyPath]: () => new Response("private", { status: 403 }),
      [accountVerifyPath]: () => Response.json({ success: true, result: { id: tokenId, status: "active" } }),
      [`${accountTokensPath}/${tokenId}`]: () => Response.json({ success: true, result: { policies: [{
        effect: "allow",
        permission_groups: [{ name: "Workers Scripts Write" }],
        resources: { [targetAccountResource]: "*" },
      }] } }),
    });
    const diagnostic = await readTokenPolicyDiagnostic({ apiToken: context.apiToken, fetchImpl });
    expect(paths()).toEqual([userVerifyPath, accountVerifyPath, `${accountTokensPath}/${tokenId}`]);
    expect(diagnostic).toMatchObject({ status: "details_read", token_active: true, target_account_scope: true, workers_admin_on_target_account: false });
    expect(diagnostic.verification.token_kind).toBe("account");
    expect(diagnostic.verification.user_verify).toEqual({ http_status: 403, error_class: "http_response" });
    expect(JSON.stringify(diagnostic)).not.toContain(tokenId);
  });

  it("reports verify_unknown with both statuses classified when user and account verify both return 401", async () => {
    const { fetchImpl, paths } = tokenFixture({
      [userVerifyPath]: () => new Response("private user 401 body", { status: 401 }),
      [accountVerifyPath]: () => new Response("private account 401 body", { status: 401 }),
    });
    const diagnostic = await readTokenPolicyDiagnostic({ apiToken: context.apiToken, fetchImpl });
    expect(paths()).toEqual([userVerifyPath, accountVerifyPath]);
    expect(diagnostic).toEqual({
      status: "verify_unknown",
      token_active: null,
      target_account_scope: null,
      workers_admin_on_target_account: null,
      verification: {
        http_status: 401,
        error_class: "http_response",
        active_status: "unknown",
        token_id_shape: "not_checked",
        token_kind: "unknown",
        user_verify: { http_status: 401, error_class: "http_response" },
        account_verify: { http_status: 401, error_class: "http_response" },
      },
    });
    expect(JSON.stringify(diagnostic)).not.toContain("private user 401 body");
    expect(JSON.stringify(diagnostic)).not.toContain("private account 401 body");
  });

  it("classifies a failed account fallback by its own error class", async () => {
    const { fetchImpl, paths } = tokenFixture({
      [userVerifyPath]: () => new Response("", { status: 401 }),
      [accountVerifyPath]: () => new Response("private malformed account body", { status: 200 }),
    });
    const diagnostic = await readTokenPolicyDiagnostic({ apiToken: context.apiToken, fetchImpl });
    expect(paths()).toEqual([userVerifyPath, accountVerifyPath]);
    expect(diagnostic.status).toBe("verify_unknown");
    expect(diagnostic.verification).toMatchObject({
      http_status: 200,
      error_class: "malformed_json",
      token_kind: "unknown",
      user_verify: { http_status: 401, error_class: "http_response" },
      account_verify: { http_status: 200, error_class: "malformed_json" },
    });
    expect(JSON.stringify(diagnostic)).not.toContain("private malformed account body");
  });

  it("reports an account-owned token scoped to a different account as having no target scope", async () => {
    const tokenId = "7".repeat(32);
    const { fetchImpl, paths } = tokenFixture({
      [userVerifyPath]: () => new Response("", { status: 401 }),
      [accountVerifyPath]: () => Response.json({ success: true, result: { id: tokenId, status: "active" } }),
      [`${accountTokensPath}/${tokenId}`]: () => Response.json({ success: true, result: { policies: [{
        effect: "allow",
        permission_groups: [{ name: "Workers Admin" }],
        resources: { [`com.cloudflare.api.account.${"0".repeat(32)}`]: "*" },
      }] } }),
    });
    const diagnostic = await readTokenPolicyDiagnostic({ apiToken: context.apiToken, fetchImpl });
    expect(paths()).toEqual([userVerifyPath, accountVerifyPath, `${accountTokensPath}/${tokenId}`]);
    expect(diagnostic).toMatchObject({ status: "details_read", target_account_scope: false, workers_admin_on_target_account: false });
    expect(diagnostic.verification.token_kind).toBe("account");
  });

  it("never treats denied account-token detail access as missing Workers Admin", async () => {
    const tokenId = "6".repeat(32);
    const { fetchImpl, paths } = tokenFixture({
      [userVerifyPath]: () => new Response("", { status: 401 }),
      [accountVerifyPath]: () => Response.json({ success: true, result: { id: tokenId, status: "active" } }),
      [`${accountTokensPath}/${tokenId}`]: () => new Response("private detail denial", { status: 403 }),
    });
    const diagnostic = await readTokenPolicyDiagnostic({ apiToken: context.apiToken, fetchImpl });
    expect(paths()).toEqual([userVerifyPath, accountVerifyPath, `${accountTokensPath}/${tokenId}`]);
    expect(diagnostic).toMatchObject({ status: "unknown_access", token_active: true, target_account_scope: null, workers_admin_on_target_account: null });
    expect(diagnostic.verification.token_kind).toBe("account");
    expect(JSON.stringify(diagnostic)).not.toContain("private detail denial");
  });

  it("charges the account fallback to the same 45-second budget", async () => {
    let clock = 0;
    const { fetchImpl, paths } = tokenFixture({
      [userVerifyPath]: () => { clock = 45_000; return new Response("", { status: 401 }); },
    });
    const diagnostic = await readTokenPolicyDiagnostic({ apiToken: context.apiToken, fetchImpl, now: () => clock });
    expect(paths()).toEqual([userVerifyPath]);
    expect(diagnostic.status).toBe("verify_unknown");
    expect(diagnostic.verification).toMatchObject({
      error_class: "timeout",
      token_kind: "unknown",
      user_verify: { http_status: 401, error_class: "http_response" },
      account_verify: { http_status: null, error_class: "timeout" },
    });
  });

  it("allows token paths only for the user endpoints and the fixed target account", () => {
    const tokenId = "a".repeat(32);
    for (const path of [
      "/user/tokens/verify",
      `/user/tokens/${tokenId}`,
      `/accounts/${READBACK_TARGET.accountId}/tokens/verify`,
      `/accounts/${READBACK_TARGET.accountId}/tokens/${tokenId}`,
    ]) expect(assertTokenDiagnosticPath(path)).toBe(true);
    for (const path of [
      `/accounts/${"0".repeat(32)}/tokens/verify`,
      `/accounts/${"0".repeat(32)}/tokens/${tokenId}`,
      `/accounts/${READBACK_TARGET.accountId.toUpperCase()}/tokens/verify`,
      `/accounts/${READBACK_TARGET.accountId}/tokens`,
      `/accounts/${READBACK_TARGET.accountId}/tokens/`,
      `/accounts/${READBACK_TARGET.accountId}/tokens/${tokenId}/value`,
      `/accounts/${READBACK_TARGET.accountId}/tokens/${"a".repeat(31)}`,
      `/accounts/${READBACK_TARGET.accountId}/tokens/verify?x=1`,
      `/accounts/${READBACK_TARGET.accountId}/tokens/permission_groups`,
      `/accounts/${READBACK_TARGET.accountId}/workers/scripts`,
      `/user/tokens/${tokenId}/value`,
    ]) expect(() => assertTokenDiagnosticPath(path)).toThrow(ReadbackError);
  });

  it("never treats denied detail access as absent token or missing Workers Admin", async () => {
    const calls = [];
    const fetchImpl = async (url, init) => {
      calls.push({ url: String(url), init });
      if (new URL(url).pathname.endsWith("/verify")) {
        return Response.json({ success: true, result: { id: "b".repeat(32), status: "active" } });
      }
      return new Response("private provider message", { status: 403 });
    };
    const diagnostic = await readTokenPolicyDiagnostic({ apiToken: context.apiToken, fetchImpl });
    expect(diagnostic).toEqual({
      status: "unknown_access",
      token_active: true,
      target_account_scope: null,
      workers_admin_on_target_account: null,
      verification: activeVerification,
    });
    expect(calls).toHaveLength(2);
    expect(JSON.stringify(diagnostic)).not.toContain("private provider message");
  });

  it("does not request token metadata unless the exact verify response is active", async () => {
    const calls = [];
    const fetchImpl = async (url, init) => {
      calls.push({ url: String(url), init });
      return Response.json({ success: true, result: { id: "c".repeat(32), status: "expired" } });
    };
    const diagnostic = await readTokenPolicyDiagnostic({ apiToken: context.apiToken, fetchImpl });
    expect(diagnostic).toEqual({
      status: "inactive",
      token_active: false,
      target_account_scope: null,
      workers_admin_on_target_account: null,
      verification: inactiveVerification,
    });
    expect(calls).toHaveLength(1);
  });

  it("uses one combined 45-second budget without retrying a slow verification", async () => {
    let clock = 0;
    const calls = [];
    const diagnostic = await readTokenPolicyDiagnostic({
      apiToken: context.apiToken,
      now: () => clock,
      fetchImpl: async (url, init) => {
        calls.push({ url: String(url), init });
        clock = 45_000;
        return Response.json({ success: true, result: { id: "1".repeat(32), status: "active" } });
      },
    });
    expect(calls).toHaveLength(1);
    expect(diagnostic).toEqual({
      status: "details_unknown",
      token_active: true,
      target_account_scope: null,
      workers_admin_on_target_account: null,
      verification: activeVerification,
    });
  });

  it("keeps account policy unknown for wildcard or unrecognized resources", async () => {
    const fetchImpl = async (url) => {
      const path = new URL(url).pathname;
      const result = path.endsWith("/verify")
        ? { id: "d".repeat(32), status: "active" }
        : { policies: [{
          effect: "allow",
          permission_groups: [{ name: "Workers Admin" }],
          resources: { "com.cloudflare.api.account.*": "*" },
        }] };
      return Response.json({ success: true, result });
    };
    expect(await readTokenPolicyDiagnostic({ apiToken: context.apiToken, fetchImpl })).toEqual({
      status: "policy_scope_unknown",
      token_active: true,
      target_account_scope: null,
      workers_admin_on_target_account: null,
      verification: activeVerification,
    });
  });

  it("reports no Workers Admin only when the complete account-scoped detail is readable", async () => {
    const fetchImpl = async (url) => {
      const path = new URL(url).pathname;
      const result = path.endsWith("/verify")
        ? { id: "f".repeat(32), status: "active" }
        : { policies: [
          {
            effect: "allow",
            permission_groups: [{ name: "Workers Scripts Write" }],
            resources: { [`com.cloudflare.api.account.${READBACK_TARGET.accountId}`]: "*" },
          },
        ] };
      return Response.json({ success: true, result });
    };
    expect(await readTokenPolicyDiagnostic({ apiToken: context.apiToken, fetchImpl })).toEqual({
      status: "details_read",
      token_active: true,
      target_account_scope: true,
      workers_admin_on_target_account: false,
      verification: activeVerification,
    });
  });

  it("keeps a conflicting allow and deny for Workers Admin unknown", async () => {
    const fetchImpl = async (url) => {
      const path = new URL(url).pathname;
      const result = path.endsWith("/verify")
        ? { id: "a".repeat(32), status: "active" }
        : { policies: [
          {
            effect: "allow",
            permission_groups: [{ name: "Workers Admin" }],
            resources: { [`com.cloudflare.api.account.${READBACK_TARGET.accountId}`]: "*" },
          },
          {
            effect: "deny",
            permission_groups: [{ name: "Workers Admin" }],
            resources: { [`com.cloudflare.api.account.${READBACK_TARGET.accountId}`]: "*" },
          },
        ] };
      return Response.json({ success: true, result });
    };
    expect(await readTokenPolicyDiagnostic({ apiToken: context.apiToken, fetchImpl })).toEqual({
      status: "policy_conflict",
      token_active: true,
      target_account_scope: null,
      workers_admin_on_target_account: null,
      verification: activeVerification,
    });
  });

  it("adds a failed policy-detail read as diagnostic-only receipt data", async () => {
    const runnerTemp = await mkdtemp(join(tmpdir(), "b216-token-diagnostic-"));
    const { fetchImpl } = apiFixture();
    try {
      const receipt = await writeReadbackReceipt({ ...context, runnerTemp }, {
        fetchImpl: async (url, init) => {
          const path = new URL(url).pathname;
          if (path.startsWith("/client/v4/accounts/")) return fetchImpl(url, init);
          if (path.endsWith("/verify")) return Response.json({ success: true, result: { id: "e".repeat(32), status: "active" } });
          return new Response("private provider message", { status: 403 });
        },
        includeTokenPolicyDiagnostic: true,
      });
      expect(receipt.status).toBe("complete");
      expect(receipt.worker).toEqual({ exists: true, inventory_count: 1 });
      expect(receipt.token_policy_diagnostic).toEqual({
        status: "unknown_access",
        token_active: true,
        target_account_scope: null,
        workers_admin_on_target_account: null,
        verification: activeVerification,
      });
      expect(JSON.stringify(receipt)).not.toContain("private provider message");
      expect(JSON.stringify(receipt)).not.toContain(context.apiToken);
      expect(JSON.stringify(receipt)).not.toContain("e".repeat(32));
      const savedReceiptPath = join(runnerTemp, "b216-receiver-readback-receipt.json");
      expect(JSON.parse(await readFile(savedReceiptPath, "utf8"))).toEqual(receipt);
      expect((await stat(savedReceiptPath)).mode & 0o777).toBe(0o600);
    } finally {
      await rm(runnerTemp, { recursive: true, force: true });
    }
  });

  // Run 36977214852 recorded only `provider_response_rejected`: no endpoint, and no
  // token diagnostic, because the diagnostic ran after the refused inventory read.
  it("runs the token diagnostic first and keeps it, plus the classified refused read, when inventory fails", async () => {
    const runnerTemp = await mkdtemp(join(tmpdir(), "b216-readback-refused-"));
    const tokenId = "5".repeat(32);
    const order = [];
    try {
      const receipt = await writeReadbackReceipt({ ...context, runnerTemp }, {
        fetchImpl: async (url) => {
          const path = new URL(url).pathname;
          order.push(path);
          if (path === userVerifyPath) return new Response("private user rejection body", { status: 401 });
          if (path === accountVerifyPath) return Response.json({ success: true, result: { id: tokenId, status: "active" } });
          if (path === `${accountTokensPath}/${tokenId}`) return Response.json({ success: false, errors: [{ code: 9109, message: "private detail" }] }, { status: 403 });
          return Response.json({ success: false, errors: [{ code: 10000, message: `Authentication error for ${READBACK_TARGET.accountId}` }] }, { status: 403 });
        },
        includeTokenPolicyDiagnostic: true,
      });
      expect(receipt).toMatchObject({
        status: "failed_closed",
        failure_code: "provider_response_rejected",
        read_failure: { endpoint: "scripts_list", http_status: 403, cf_error_codes: [10000], message_class: "authentication" },
        token_verifies: true,
        token_policy_diagnostic: { status: "unknown_access", token_active: true, verification: { token_kind: "account", active_status: "active" } },
      });
      // Each refused token request goes through the same classifier as the inventory.
      expect(receipt.token_read_failures).toEqual([
        { endpoint: "token_verify_user", http_status: 401, cf_error_codes: [], message_class: "malformed_response" },
        { endpoint: "token_details_account", http_status: 403, cf_error_codes: [9109], message_class: "authentication" },
      ]);
      expect(order.slice(0, 3)).toEqual([userVerifyPath, accountVerifyPath, `${accountTokensPath}/${tokenId}`]);
      expect(order[3]).toBe(`/client/v4/accounts/${READBACK_TARGET.accountId}/workers/scripts`);
      const saved = await readFile(join(runnerTemp, "b216-receiver-readback-receipt.json"), "utf8");
      for (const secret of [context.apiToken, tokenId, "private user rejection body", "private detail", "Authentication error for"]) {
        expect(saved).not.toContain(secret);
      }
    } finally {
      await rm(runnerTemp, { recursive: true, force: true });
    }
  });

  it("classifies two refused verify requests with their codes", async () => {
    const runnerTemp = await mkdtemp(join(tmpdir(), "b216-readback-verify-403-"));
    try {
      const receipt = await writeReadbackReceipt({ ...context, runnerTemp }, {
        fetchImpl: async (url) => {
          const path = new URL(url).pathname;
          if (path === userVerifyPath) return Response.json({ success: false, errors: [{ code: 9109, message: "Unauthorized to access requested resource" }] }, { status: 403 });
          if (path === accountVerifyPath) return Response.json({ success: false, errors: [{ code: 10000, message: "private detail" }, { code: 7003, message: "x" }] }, { status: 403 });
          return Response.json({ success: false, errors: [{ code: 10000, message: "private detail" }] }, { status: 403 });
        },
        includeTokenPolicyDiagnostic: true,
      });
      expect(receipt.token_verifies).toBe(false);
      expect(receipt.token_read_failures).toEqual([
        { endpoint: "token_verify_user", http_status: 403, cf_error_codes: [9109], message_class: "authentication" },
        { endpoint: "token_verify_account", http_status: 403, cf_error_codes: [10000, 7003], message_class: "authentication" },
      ]);
      expect(receipt.read_failure).toEqual({ endpoint: "scripts_list", http_status: 403, cf_error_codes: [10000], message_class: "authentication" });
      expect(JSON.stringify(receipt)).not.toContain("private detail");
    } finally {
      await rm(runnerTemp, { recursive: true, force: true });
    }
  });

  it("refuses a bad dispatch context before any provider request, token diagnostic included", async () => {
    const runnerTemp = await mkdtemp(join(tmpdir(), "b216-readback-context-"));
    let calls = 0;
    try {
      const receipt = await writeReadbackReceipt({ ...context, repository: "attacker/fork", runnerTemp }, {
        fetchImpl: async () => { calls += 1; return Response.json({ success: true, result: {} }); },
        includeTokenPolicyDiagnostic: true,
      });
      expect(calls).toBe(0);
      expect(receipt).toMatchObject({ status: "failed_closed", failure_code: "repository_mismatch", read_failure: null });
      expect(receipt).not.toHaveProperty("token_policy_diagnostic");
      expect(receipt).not.toHaveProperty("token_read_failures");
    } finally {
      await rm(runnerTemp, { recursive: true, force: true });
    }
  });

  it("records a token that cannot verify at all, and the refused read that followed", async () => {
    const runnerTemp = await mkdtemp(join(tmpdir(), "b216-readback-unverified-"));
    try {
      const receipt = await writeReadbackReceipt({ ...context, runnerTemp }, {
        fetchImpl: async (url) => {
          const path = new URL(url).pathname;
          if (path.endsWith("/verify")) return Response.json({ success: false, errors: [{ code: 1000, message: "Invalid API Token" }] }, { status: 401 });
          if (path.endsWith("/versions")) return new Response("not json", { status: 500 });
          return Response.json({ success: true, result: [{ id: READBACK_TARGET.workerName, routes: [] }] });
        },
        includeTokenPolicyDiagnostic: true,
      });
      expect(receipt).toMatchObject({
        status: "failed_closed",
        token_verifies: false,
        read_failure: { endpoint: "worker_versions", http_status: 500, cf_error_codes: [], message_class: "malformed_response" },
      });
      expect(receipt.token_policy_diagnostic.verification.token_kind).toBe("unknown");
      expect(receipt.token_read_failures).toEqual([
        { endpoint: "token_verify_user", http_status: 401, cf_error_codes: [1000], message_class: "authentication" },
        { endpoint: "token_verify_account", http_status: 401, cf_error_codes: [1000], message_class: "authentication" },
      ]);
    } finally {
      await rm(runnerTemp, { recursive: true, force: true });
    }
    expect(tokenVerifies({ status: "token_missing" })).toBeNull();
    expect(tokenVerifies(null)).toBeNull();
    expect(tokenVerifies({ status: "details_read", verification: { token_kind: "user" } })).toBe(true);
  });

  it("writes an account-owned token diagnostic to the receipt without the token, its ID, or bodies", async () => {
    const runnerTemp = await mkdtemp(join(tmpdir(), "b216-account-token-diagnostic-"));
    const tokenId = "5".repeat(32);
    const inventory = apiFixture();
    const token = tokenFixture({
      [userVerifyPath]: () => new Response("private user rejection body", { status: 401 }),
      [accountVerifyPath]: () => Response.json({ success: true, result: { id: tokenId, status: "active" } }),
      [`${accountTokensPath}/${tokenId}`]: () => Response.json({ success: true, result: { id: tokenId, name: "private token name", policies: [{
        effect: "allow",
        permission_groups: [{ name: "Workers Admin" }],
        resources: { [targetAccountResource]: "*" },
      }] } }),
    });
    try {
      const receipt = await writeReadbackReceipt({ ...context, runnerTemp }, {
        fetchImpl: async (url, init) => {
          const path = new URL(url).pathname;
          if (path === userVerifyPath || path.startsWith(`${accountTokensPath}/`)) return token.fetchImpl(url, init);
          return inventory.fetchImpl(url, init);
        },
        includeTokenPolicyDiagnostic: true,
      });
      expect(receipt.status).toBe("complete");
      expect(token.paths()).toEqual([userVerifyPath, accountVerifyPath, `${accountTokensPath}/${tokenId}`]);
      expect(receipt.token_policy_diagnostic).toMatchObject({
        status: "details_read",
        token_active: true,
        target_account_scope: true,
        workers_admin_on_target_account: true,
        verification: { token_kind: "account" },
      });
      const saved = await readFile(join(runnerTemp, "b216-receiver-readback-receipt.json"), "utf8");
      for (const secret of [context.apiToken, tokenId, "private user rejection body", "private token name"]) {
        expect(saved).not.toContain(secret);
      }
    } finally {
      await rm(runnerTemp, { recursive: true, force: true });
    }
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
    expect(receipt.routes).toEqual({ status: "known", count: 0, pattern_sha256: [] });
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

  it("serializes only route-pattern hashes, never routes, response bodies, or request URLs", async () => {
    const routePattern = "alerts.example.invalid/*";
    const { fetchImpl } = apiFixture({
      [`/accounts/${READBACK_TARGET.accountId}/workers/scripts`]: {
        success: true,
        result: [{ id: READBACK_TARGET.workerName, routes: [{ id: "route-id", pattern: routePattern, script: READBACK_TARGET.workerName }] }],
      },
    });
    const receipt = await readWorkerInventory({ context, fetchImpl });
    const serialized = JSON.stringify(receipt);
    expect(serialized).not.toContain(routePattern);
    expect(serialized).not.toContain("route-id");
    expect(serialized).not.toContain("test-token-never-real");
    expect(receipt.routes.pattern_sha256).toEqual([
      createHash("sha256").update(routePattern, "utf8").digest("hex"),
    ]);
  });
});
