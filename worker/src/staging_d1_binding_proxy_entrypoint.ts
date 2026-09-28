import { WorkerEntrypoint } from "cloudflare:workers";
import type { Env } from "./index_env.js";
import { handleStagingD1BindingRequest } from "./staging_d1_binding_proxy.js";

/** Loopback-only service binding. The Worker default fetch does not route here. */
export class StagingD1BindingProxy extends WorkerEntrypoint<Env> {
  override fetch(request: Request): Promise<Response> {
    return handleStagingD1BindingRequest(request, this.env);
  }
}
