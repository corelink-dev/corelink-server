import { execFileSync } from "node:child_process";
import { writeReadbackReceipt } from "./readback-route.mjs";

const receipt = await writeReadbackReceipt({
  repository: process.env.GITHUB_REPOSITORY,
  ref: process.env.GITHUB_REF,
  sha: process.env.GITHUB_SHA,
  checkoutSha: execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8" }).trim(),
  readbackOnly: "true",
  apiToken: process.env.B216_CF_RECEIVER_WRITE_TOKEN,
  runnerTemp: process.env.RUNNER_TEMP,
}, { includeTokenPolicyDiagnostic: true });
if (receipt.status !== "complete") process.exitCode = 1;
