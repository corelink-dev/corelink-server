import type { Env } from "./index_env";

type Equal<Left, Right> =
  (<Value>() => Value extends Left ? 1 : 2) extends
  (<Value>() => Value extends Right ? 1 : 2)
    ? true
    : false;
type Assert<Condition extends true> = Condition;

type StagingAdmissionBindings = Pick<
  Env,
  "CORELINK_ENVIRONMENT" | "CORELINK_STAGING_LOAD_TEST_ADMISSION_KEY"
>;

// Compile-time proof of both the absent and present binding shapes.
export type StagingAdmissionEnvContract = {
  absentBindingsAreAccepted: Assert<{} extends StagingAdmissionBindings ? true : false>;
  presentBindingsAreAccepted: Assert<
    {
      CORELINK_ENVIRONMENT: "staging";
      CORELINK_STAGING_LOAD_TEST_ADMISSION_KEY: "configured-outside-source";
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
};
