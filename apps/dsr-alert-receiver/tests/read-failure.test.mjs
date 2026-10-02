import { describe, expect, it } from "vitest";
import { READ_FAILURE_ENDPOINTS, classifyReadFailure, labelReadEndpoint, sanitizeReadFailure } from "../scripts/read-failure.mjs";
import { RECEIVER_TARGET } from "../scripts/receiver-target.mjs";

const account = `/accounts/${RECEIVER_TARGET.accountId}`;
const worker = `${account}/workers/scripts/${RECEIVER_TARGET.workerName}`;
const uuid = "c0ffee00-0b16-4000-8000-0000000006a1";
const zone = "f".repeat(32);
const tokenId = "e".repeat(32);

describe("B-216 allowlisted read-failure classification", () => {
  it("labels every receiver request path with a closed endpoint label", () => {
    for (const [path, label] of [
      [account, "account"],
      [`${account}/workers/scripts`, "scripts_list"],
      [worker, "worker_script"],
      [`${worker}/versions?page=1&per_page=100`, "worker_versions"],
      [`${worker}/versions?per_page=100&deployable=true`, "worker_versions"],
      [`${worker}/versions/${uuid}`, "worker_version"],
      [`${worker}/deployments?page=1&per_page=100`, "worker_deployments"],
      [`${worker}/secrets`, "worker_secrets"],
      [`${worker}/subdomain`, "worker_subdomain"],
      [`${account}/workers/subdomain`, "account_workers_subdomain"],
      [`${account}/workers/domains`, "custom_domains"],
      [`/zones?account.id=${RECEIVER_TARGET.accountId}&page=1&per_page=50`, "zones_list"],
      [`/zones/${zone}/workers/routes`, "zone_routes"],
      [`${account}/workers/services/${RECEIVER_TARGET.workerName}/environments/production/routes`, "service_routes"],
      [`${account}/d1/database?name=${RECEIVER_TARGET.databaseName}&page=1&per_page=100`, "d1_list"],
      [`${account}/d1/database/${uuid}/query`, "d1_query"],
      ["/user/tokens/verify", "token_verify_user"],
      [`${account}/tokens/verify`, "token_verify_account"],
      [`/user/tokens/${tokenId}`, "token_details_user"],
      [`${account}/tokens/${tokenId}`, "token_details_account"],
      ["/accounts/x/unknown", "other"],
      [`${worker}/schedules`, "other"],
    ]) {
      expect(labelReadEndpoint(path), path).toBe(label);
      expect(READ_FAILURE_ENDPOINTS).toContain(label);
    }
  });

  it.each([
    [403, { success: false, errors: [{ code: 10000, message: "Authentication error" }] }, [10000], "authentication"],
    [403, { success: false, errors: [{ code: 9109, message: "Unauthorized to access requested resource" }] }, [9109], "authentication"],
    [403, { success: false, errors: [{ code: 10000 }] }, [10000], "authentication"],
    [403, { success: false, errors: [{ code: 7003, message: "You do not have permission to perform this action" }] }, [7003], "permission"],
    [403, { success: false, errors: [] }, [], "permission"],
    [401, { success: false, errors: [] }, [], "authentication"],
    [404, { success: false, errors: [{ code: 10007, message: "workers.api.error.script_not_found" }] }, [10007], "not_found"],
    [429, { success: false, errors: [{ code: 971, message: "Please wait and consider throttling your request speed" }] }, [971], "rate_limited"],
    [502, { success: false, errors: [{ code: 10013, message: "An unknown error has occurred" }] }, [10013], "server_error"],
    [200, { success: false, errors: [] }, [], "rejected_without_detail"],
    [400, { success: false, errors: [{ code: 8000000, message: "x" }, { message: "y" }] }, [], "other"],
  ])("classifies HTTP %i with its Cloudflare codes", (status, payload, codes, messageClass) => {
    const failure = classifyReadFailure({ path: `${account}/workers/scripts`, status, payload });
    expect(failure).toEqual({ endpoint: "scripts_list", http_status: status, cf_error_codes: codes, message_class: messageClass });
  });

  it("classifies transport and malformed responses without a body", () => {
    expect(classifyReadFailure({ path: "/zones", transport: true })).toEqual({ endpoint: "zones_list", http_status: null, cf_error_codes: [], message_class: "transport" });
    expect(classifyReadFailure({ path: "/zones", status: 403, malformed: true })).toEqual({ endpoint: "zones_list", http_status: 403, cf_error_codes: [], message_class: "malformed_response" });
    expect(classifyReadFailure({ path: `/accounts/${"a".repeat(32)}/workers/scripts`, status: 200, payload: { errors: [{ code: 10000 }] }, unexpectedShape: true }))
      .toEqual({ endpoint: "scripts_list", http_status: 200, cf_error_codes: [], message_class: "unexpected_shape" });
    expect(sanitizeReadFailure({ endpoint: "scripts_list", http_status: 200, cf_error_codes: [], message_class: "unexpected_shape" }).message_class).toBe("unexpected_shape");
  });

  it("caps and de-duplicates Cloudflare codes and never copies text, paths or IDs", () => {
    const payload = { success: false, errors: [...Array.from({ length: 12 }, (_, index) => ({ code: 1100 + index, message: `secret message ${tokenId}` })), { code: 1100 }] };
    const failure = classifyReadFailure({ path: `${account}/tokens/${tokenId}`, status: 403, payload });
    expect(failure.cf_error_codes).toEqual([1100, 1101, 1102, 1103, 1104, 1105, 1106, 1107]);
    const serialized = JSON.stringify(failure);
    for (const leaked of ["secret message", tokenId, RECEIVER_TARGET.accountId, "/accounts/"]) expect(serialized).not.toContain(leaked);
  });

  it("drops forged fields when a record is copied into a receipt", () => {
    expect(sanitizeReadFailure({ endpoint: "/accounts/x", http_status: 99, cf_error_codes: [10000, "10001", 10000, -1], message_class: "Authentication error", body: "x" }))
      .toEqual({ endpoint: "other", http_status: null, cf_error_codes: [10000], message_class: "other" });
    expect(sanitizeReadFailure(null)).toBeNull();
    expect(sanitizeReadFailure("x")).toBeNull();
  });
});
