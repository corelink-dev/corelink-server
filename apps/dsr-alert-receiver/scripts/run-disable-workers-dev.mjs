import { mkdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { execFileSync } from "node:child_process";
import { makeCloudflareApi, providerFailureFields, TARGET } from "./deploy-route.mjs";
import { disableWorkersDev } from "./synthetic-exercise.mjs";

const context = {
  repository: process.env.GITHUB_REPOSITORY,
  ref: process.env.GITHUB_REF,
  sha: process.env.GITHUB_SHA,
  checkoutSha: execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim(),
  apiToken: process.env.B216_CF_RECEIVER_WRITE_TOKEN,
};
if (context.repository !== TARGET.repository || context.ref !== "refs/heads/main"
  || !/^[0-9a-f]{40}$/.test(context.sha ?? "") || context.checkoutSha !== context.sha
  || !context.apiToken) throw new Error("disable_workers_dev_dispatch_invalid");
const receipt = {
  schema_version: 1,
  issue: 1678,
  mode: "disable_workers_dev",
  repository: TARGET.repository,
  reviewed_main_sha: context.sha,
  account_id: TARGET.accountId,
  worker_name: TARGET.workerName,
  status: "started",
};
const path = join(process.env.RUNNER_TEMP || tmpdir(), "b216-receiver-disable-receipt.json");
try {
  Object.assign(receipt, await disableWorkersDev({ api: makeCloudflareApi(context.apiToken) }));
  receipt.status = "complete";
} catch (error) {
  receipt.status = "failed_closed";
  receipt.failure_code = typeof error?.code === "string" ? error.code : "workers_dev_disable_failed_closed";
  Object.assign(receipt, providerFailureFields(error));
}
await mkdir(dirname(path), { recursive: true });
await writeFile(path, `${JSON.stringify(receipt, null, 2)}\n`, { mode: 0o600 });
if (receipt.status !== "complete") process.exitCode = 1;
