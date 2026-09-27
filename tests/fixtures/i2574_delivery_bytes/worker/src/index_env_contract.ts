import type { Env } from "./index_env";

type Equal<Left, Right> =
  (<Value>() => Value extends Left ? 1 : 2) extends
  (<Value>() => Value extends Right ? 1 : 2)
    ? true
    : false;
type Assert<Condition extends true> = Condition;

type StagingAdmissionBindings = Pick<
  Env,
  | "CORELINK_ENVIRONMENT"
  | "CORELINK_STAGING_LOAD_TEST_ADMISSION_KEY"
  | "CORELINK_STAGING_GRPC_PROBE_TOKEN"
  | "CORELINK_STAGING_GRPC_PROBE_EXPIRES_AT_MS"
  | "CORELINK_STAGING_GRPC_PROBE_DEPLOYMENT_SHA"
  | "CORELINK_STAGING_GRPC_PROBE_WORKER_NAME"
>;

// Compile-time proof of both the absent and present binding shapes.
export type StagingAdmissionEnvContract = {
  absentBindingsAreAccepted: Assert<{} extends StagingAdmissionBindings ? true : false>;
  presentBindingsAreAccepted: Assert<
    {
      CORELINK_ENVIRONMENT: "staging";
      CORELINK_STAGING_LOAD_TEST_ADMISSION_KEY: "configured-outside-source";
      CORELINK_STAGING_GRPC_PROBE_TOKEN: "configured-outside-source";
      CORELINK_STAGING_GRPC_PROBE_EXPIRES_AT_MS: "1800000000000";
      CORELINK_STAGING_GRPC_PROBE_DEPLOYMENT_SHA: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
      CORELINK_STAGING_GRPC_PROBE_WORKER_NAME: "corelink-staging";
    } extends StagingAdmissionBindings
      ? true
      : false
  >;
  environmentIsOptionalString: Assert<
    Equal<Env["CORELINK_ENVIRONMENT"], string | undefined>
  >;
  admissionKeyIsOptionalString: Assert<
    Equal<Env["CORELINK_STAGING_LOAD_TEST_ADMISSION_KEY"], string | undefined>
  >;
  probeTokenIsOptionalString: Assert<
    Equal<Env["CORELINK_STAGING_GRPC_PROBE_TOKEN"], string | undefined>
  >;
  probeExpiryIsOptionalString: Assert<
    Equal<Env["CORELINK_STAGING_GRPC_PROBE_EXPIRES_AT_MS"], string | undefined>
  >;
  probeDeploymentShaIsOptionalString: Assert<
    Equal<Env["CORELINK_STAGING_GRPC_PROBE_DEPLOYMENT_SHA"], string | undefined>
  >;
  probeWorkerNameIsOptionalString: Assert<
    Equal<Env["CORELINK_STAGING_GRPC_PROBE_WORKER_NAME"], string | undefined>
  >;
};
