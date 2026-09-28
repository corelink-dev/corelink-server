/** CoreLink Worker entry point. Domain handlers live in bounded modules. */
import * as Sentry from "@sentry/cloudflare";
import { scrubSentryEvent } from "./sentry-scrub.js";
import { CoreLinkServer } from "./durable_object.js";
import { StagingD1BindingProxy } from "./staging_d1_binding_proxy_entrypoint.js";

// Required by Cloudflare's container egress interception runtime. CoreLink
// retains its existing raw DurableObject class; only the outbound proxy
// WorkerEntrypoint is exported from the SDK.
export { ContainerProxy } from "@cloudflare/containers";
import { RolloutController } from "./rollout_controller.js";
import { EventLogDO } from "./event_log_do.js";
import { RequestMeterCoordinatorDO } from "./request_meter_coordinator_do.js";
import { RequestMeterShardDO } from "./request_meter_shard_do.js";
import { ReplicationCoordinatorDO } from "./replication_coordinator_do.js";
import { baseHandler } from "./index_fetch.js";
import type { Env } from "./index_common.js";
import type { ExportedHandler } from "@cloudflare/workers-types";

export type { Env } from "./index_common.js";
export { StagingD1BindingProxy };
export { doLocationHintForRegion, internalConsumerForPath } from "./index_common.js";
export {
  deferCapVerdictFor,
  isDsrEraseFanoutPath,
  originSubPhases,
  quotaExceededResponse,
  quotaPathFor,
  wdbControlPhase,
} from "./index_observability.js";

const sentryHandler = Sentry.withSentry(
  (env: Env) => ({
    dsn: env.SENTRY_DSN ?? "",
    environment: env.ENVIRONMENT,
    release: env.SENTRY_RELEASE ?? "unknown",
    sendDefaultPii: false,
    tracesSampleRate: 0.1,
    sampleRate: 1.0,
    beforeSend(event: Sentry.ErrorEvent) {
      return scrubSentryEvent(event);
    },
    beforeSendTransaction(event) {
      return scrubSentryEvent(event);
    },
  }),
  baseHandler as unknown as Parameters<typeof Sentry.withSentry>[1],
) as ExportedHandler<Env>;

const handler: ExportedHandler<Env> = {
  ...sentryHandler,
  scheduled: baseHandler.scheduled!,
};

export default handler;
export {
  CoreLinkServer,
  RolloutController,
  EventLogDO,
  ReplicationCoordinatorDO,
  RequestMeterCoordinatorDO,
  RequestMeterShardDO,
};
