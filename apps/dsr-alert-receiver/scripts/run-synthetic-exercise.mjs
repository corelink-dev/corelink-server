import { readFile } from "node:fs/promises";
import { execFileSync } from "node:child_process";
import { join } from "node:path";
import { TARGET } from "./deploy-route.mjs";
import { runSyntheticReceiverExercise } from "./synthetic-exercise.mjs";

const worktree = process.env.GITHUB_WORKSPACE || process.cwd();
const appDir = join(worktree, "apps/dsr-alert-receiver");
const context = {
  repository: process.env.GITHUB_REPOSITORY,
  ref: process.env.GITHUB_REF,
  sha: process.env.GITHUB_SHA,
  checkoutSha: execFileSync("git", ["rev-parse", "HEAD"], { cwd: worktree, encoding: "utf8" }).trim(),
  apiToken: process.env.B216_CF_RECEIVER_WRITE_TOKEN,
  receiverToken: process.env.B216_DSR_ALERT_RECEIVER_TOKEN,
  runId: process.env.GITHUB_RUN_ID,
  runAttempt: process.env.GITHUB_RUN_ATTEMPT,
};
const receiptPath = join(process.env.RUNNER_TEMP || "/tmp", "b216-receiver-synthetic-receipt.json");
const receipt = await runSyntheticReceiverExercise({
  context,
  config: await readFile(join(appDir, "wrangler.toml"), "utf8"),
  migration: await readFile(join(appDir, "migrations", TARGET.migration), "utf8"),
  receiptPath,
});
if (receipt.status !== "complete") {
  process.stderr.write(`B-216 synthetic exercise stopped: ${receipt.failure_code || receipt.status}; cleanup=${receipt.workers_dev_cleanup}\n`);
  process.exitCode = 1;
}
