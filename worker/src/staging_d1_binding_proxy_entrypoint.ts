import { WorkerEntrypoint } from "cloudflare:workers";
import type { Env } from "./index_env.js";
import { handleStagingD1BindingRequest } from "./staging_d1_binding_proxy.js";
import { isStagingD1HttpDeadline, type StagingD1HttpDeadline } from "./staging_d1_http_lifetime.js";

/** Loopback-only service binding. The Worker default fetch does not route here. */
export class StagingD1BindingProxy extends WorkerEntrypoint<Env> {
  override fetch(request: Request): Promise<Response> {
    const props: unknown = this.ctx.props;
    let deadline: StagingD1HttpDeadline;
    try {
      if (isEmptyProps(props)) return handleStagingD1BindingRequest(request, this.env);
      if (!isStagingD1HttpDeadline(props, this.env.SENTRY_RELEASE ?? "")) {
        return Promise.resolve(proxyError());
      }
      deadline = props;
    } catch {
      return Promise.resolve(proxyError());
    }
    return handleStagingD1BindingRequest(request, this.env, deadline);
  }
}

function isEmptyProps(value: unknown): boolean {
  return typeof value === "object" && value !== null && !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype && Reflect.ownKeys(value).length === 0;
}

function proxyError(): Response {
  return Response.json({ result: [], success: false, errors: [{ message: "D1 binding operation failed" }] },
    { status: 502, headers: { "cache-control": "no-store" } });
}
