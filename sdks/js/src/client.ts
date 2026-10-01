import { blake3Hex, isCanonicalDigest, type BlobDigest } from "./digest.js";
import {
  ConnectError,
  CoreLinkError,
  DigestMismatchError,
  ServerError,
  errorForStatus,
} from "./errors.js";
import type {
  ClientConfig,
  GetOptions,
  PutOptions,
  RetryConfig,
  StatResult,
  TenantId,
} from "./types.js";

const DEFAULT_BASE_URL = "https://corelink-api.humangr.com";
const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_RETRY: RetryConfig = {
  maxAttempts: 3,
  baseDelayMs: 200,
  maxDelayMs: 10_000,
};

function trimTrailingSlashes(value: string): string {
  let end = value.length;
  while (end > 0 && value.charCodeAt(end - 1) === 0x2f) end -= 1;
  return value.slice(0, end);
}

/** Read `CORELINK_PAT` from the environment when available (Node/Workers). */
function envPat(): string | undefined {
  if (typeof process !== "undefined" && process.env) {
    return process.env.CORELINK_PAT;
  }
  return undefined;
}

function debugEnabled(): boolean {
  return (
    typeof process !== "undefined" &&
    !!process.env &&
    process.env.CORELINK_LOG === "debug"
  );
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

/** Low-level response captured by the request pipeline. */
interface RawResponse {
  status: number;
  bytes: Uint8Array;
  /** `Content-Length` response header, when the server sends one. */
  contentLength?: number;
}

/**
 * The CoreLink JS/TS client.
 *
 * Grounded 1:1 on the wired container routes:
 * - CAS  `GET`/`PUT` `/v1/cas/{tenant}/{hash}`   (BLAKE3-keyed)
 * - AC   `GET`/`PUT` `/v1/ac/{tenant}/{action_digest}`
 *
 * Auth is a PAT bearer token; the tenant is the sole isolation key.
 *
 * ```ts
 * import { CoreLinkClient } from "@corelink/client";
 *
 * const client = new CoreLinkClient({ tenantId: "acme-corp" }); // PAT from env
 * const digest = await client.put(new TextEncoder().encode("hello"));
 * const bytes = await client.get(digest); // BLAKE3-verified by default
 * ```
 */
export class CoreLinkClient {
  private readonly pat: string;
  private readonly baseUrl: string;
  private readonly tenantId: TenantId;
  private readonly clientVerify: boolean;
  private readonly timeoutMs: number;
  private readonly retry: RetryConfig;
  private readonly fetchImpl: typeof fetch;

  /** Action Cache (REAPI-style) sub-API. */
  readonly actionCache: ActionCacheApi;

  constructor(config: ClientConfig) {
    const pat = config.pat ?? envPat();
    if (!pat) {
      throw new CoreLinkError(
        "CoreLink PAT required: pass { pat } or set the CORELINK_PAT environment variable.",
      );
    }
    if (!config.tenantId) {
      throw new CoreLinkError("CoreLink tenantId is required.");
    }
    this.pat = pat;
    this.tenantId = config.tenantId;
    this.baseUrl = trimTrailingSlashes(config.baseUrl ?? DEFAULT_BASE_URL);
    this.clientVerify = config.clientVerify ?? true;
    this.timeoutMs = config.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.retry = { ...DEFAULT_RETRY, ...(config.retry ?? {}) };

    const f = config.fetch ?? (globalThis.fetch as typeof fetch | undefined);
    if (!f) {
      throw new CoreLinkError(
        "No fetch implementation available. Upgrade to Node 18+ or pass { fetch }.",
      );
    }
    this.fetchImpl = f;

    if (!this.clientVerify) {
      // eslint-disable-next-line no-console
      console.warn(
        "corelink.client.verify_disabled: BLAKE3 client-verify is OFF; downloaded bytes are unverified (DISABLE NOT RECOMMENDED).",
      );
    }

    this.actionCache = new ActionCacheApi(this);
  }

  /** Whether BLAKE3 client-verify is enabled (test inspection hook). */
  get _clientVerifyEnabled(): boolean {
    return this.clientVerify;
  }

  /**
   * Upload bytes to the CAS. Computes the BLAKE3 digest locally (the address
   * the blob lives at) and returns it. Idempotent server-side: re-uploading
   * identical bytes resolves to the same digest without double-billing.
   *
   * @throws {DigestMismatchError} if `opts.expectedDigest` disagrees with the
   *   locally computed digest, or if the server rejects the claimed hash (422).
   */
  async put(data: Uint8Array, opts: PutOptions = {}): Promise<BlobDigest> {
    const digest = blake3Hex(data);
    if (opts.expectedDigest && opts.expectedDigest !== digest) {
      throw new DigestMismatchError(
        `expectedDigest ${opts.expectedDigest} != computed ${digest}`,
      );
    }
    await this.request("PUT", this.casPath(digest), {
      body: data,
      contentType: "application/octet-stream",
    });
    return digest;
  }

  /**
   * Download a blob by digest. By default the bytes are BLAKE3-verified
   * against the requested digest; a mismatch throws {@link DigestMismatchError}
   * and the bytes are never returned.
   *
   * @throws {NotFoundError} 404 — not in this tenant's CAS.
   * @throws {GoneError} 410 — the artifact was erased.
   */
  async get(digest: BlobDigest, opts: GetOptions = {}): Promise<Uint8Array> {
    this.assertDigest(digest);
    const { bytes } = await this.request("GET", this.casPath(digest));
    const verify = opts.verify ?? this.clientVerify;
    if (verify) {
      const actual = blake3Hex(bytes);
      if (actual !== digest) {
        throw new DigestMismatchError(
          `COR_CAS_DIGEST_MISMATCH: requested ${digest} but bytes hash to ${actual}`,
          { code: "COR_CAS_DIGEST_MISMATCH" },
        );
      }
    }
    return bytes;
  }

  /**
   * Existence + size for a digest. Issues a `HEAD` request to the same CAS
   * route (mirroring the Python SDK's `stat`), so no body is transferred and
   * `sizeBytes` comes from the `Content-Length` response header. A 404/410
   * resolves to `{ exists: false, sizeBytes: 0 }`.
   */
  async stat(digest: BlobDigest): Promise<StatResult> {
    this.assertDigest(digest);
    const res = await this.rawRequest("HEAD", this.casPath(digest));
    if (res.status === 200) {
      // A HEAD response carries the size only as a header. If a server omits
      // it, report 0 rather than guessing (mirrors the Python SDK's default).
      return { digest, exists: true, sizeBytes: res.contentLength ?? 0 };
    }
    if (res.status === 404 || res.status === 410) {
      return { digest, exists: false, sizeBytes: 0 };
    }
    throw errorForStatus(res.status, decode(res.bytes), "cas");
  }

  /**
   * Close the client. The SDK holds no persistent connection pool (it uses the
   * platform `fetch`), so this is a no-op today — provided for lifecycle
   * symmetry and forward-compatibility. Safe to call any number of times.
   */
  async close(): Promise<void> {
    /* no-op */
  }

  // ---- internals (also used by ActionCacheApi) -------------------------

  /** @internal */
  casPath(hash: string): string {
    return `/v1/cas/${encodeURIComponent(this.tenantId)}/${encodeURIComponent(hash)}`;
  }

  /** @internal */
  acPath(actionDigest: string): string {
    return `/v1/ac/${encodeURIComponent(this.tenantId)}/${encodeURIComponent(actionDigest)}`;
  }

  /** @internal */
  assertDigest(digest: string): void {
    if (!isCanonicalDigest(digest)) {
      throw new CoreLinkError(
        `not a canonical CoreLink digest (want 64 lowercase hex chars): ${digest}`,
      );
    }
  }

  /**
   * Issue a request with retry/backoff, throwing a mapped {@link CoreLinkError}
   * on any non-2xx status. Used by every write path and by `get`.
   * @internal
   */
  async request(
    method: string,
    path: string,
    opts: { body?: Uint8Array; contentType?: string; context?: "cas" | "ac" } = {},
  ): Promise<RawResponse> {
    const res = await this.rawRequest(method, path, opts);
    if (res.status >= 200 && res.status < 300) {
      return res;
    }
    throw errorForStatus(res.status, decode(res.bytes), opts.context);
  }

  /**
   * Issue a request with retry/backoff and return the raw response WITHOUT
   * throwing on non-2xx (so callers like `stat` can branch on 404). Retries
   * transient failures: 429, 503, and transport errors. Method-agnostic — any
   * verb works, including `HEAD` (the captured `Content-Length` header is
   * exposed as {@link RawResponse.contentLength} for bodyless probes).
   * @internal
   */
  async rawRequest(
    method: string,
    path: string,
    opts: { body?: Uint8Array; contentType?: string } = {},
  ): Promise<RawResponse> {
    const url = `${this.baseUrl}${path}`;
    let attempt = 0;
    let lastErr: unknown;
    while (attempt < this.retry.maxAttempts) {
      attempt++;
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.timeoutMs);
      try {
        if (debugEnabled()) {
          // eslint-disable-next-line no-console
          console.error(
            JSON.stringify({ level: "debug", event: "request", method, url, attempt }),
          );
        }
        const headers: Record<string, string> = {
          authorization: `Bearer ${this.pat}`,
          "x-corelink-tenant-id": this.tenantId,
        };
        if (opts.contentType) headers["content-type"] = opts.contentType;
        const resp = await this.fetchImpl(url, {
          method,
          headers,
          body: opts.body as BodyInit | undefined,
          signal: controller.signal,
        });
        const bytes = new Uint8Array(await resp.arrayBuffer());
        const raw: RawResponse = { status: resp.status, bytes };
        const clHeader = resp.headers.get("content-length");
        if (clHeader !== null) {
          const parsed = Number.parseInt(clHeader, 10);
          if (Number.isFinite(parsed) && parsed >= 0) {
            raw.contentLength = parsed;
          }
        }
        if (this.isRetryable(resp.status) && attempt < this.retry.maxAttempts) {
          lastErr = errorForStatus(resp.status, decode(bytes));
          await this.backoff(attempt);
          continue;
        }
        return raw;
      } catch (err) {
        // Transport-level failure (DNS, reset, timeout/abort). Retry if budget
        // remains, else surface as a ConnectError.
        lastErr = err;
        if (attempt < this.retry.maxAttempts) {
          await this.backoff(attempt);
          continue;
        }
        if (err instanceof CoreLinkError) throw err;
        throw new ConnectError(`request to ${url} failed: ${String(err)}`, {
          cause: err,
        });
      } finally {
        clearTimeout(timer);
      }
    }
    // Retry budget exhausted on a retryable status.
    if (lastErr instanceof CoreLinkError) throw lastErr;
    throw new ServerError(`request to ${url} exhausted retries`, { cause: lastErr });
  }

  private isRetryable(status: number): boolean {
    return status === 429 || status === 503;
  }

  private async backoff(attempt: number): Promise<void> {
    const base = this.retry.baseDelayMs * 2 ** (attempt - 1);
    const capped = Math.min(base, this.retry.maxDelayMs);
    const jittered = Math.floor(capped * (0.5 + Math.random() * 0.5));
    await sleep(jittered);
  }
}

/**
 * Action Cache sub-API. CoreLink stores an opaque `ActionResult` byte payload
 * keyed by a 64-hex action digest (`routes/ac.rs`); this SDK is honest about
 * that shape — the payload is whatever your build tool serialized (e.g. a REAPI
 * `ActionResult` protobuf). Use {@link CoreLinkClient} `put`/`get` for the
 * referenced output blobs.
 */
export class ActionCacheApi {
  constructor(private readonly client: CoreLinkClient) {}

  /**
   * Look up the stored `ActionResult` bytes for an action digest.
   * @throws {ActionCacheMiss} 404 — no result cached for this action.
   */
  async get(actionDigest: string): Promise<Uint8Array> {
    this.client.assertDigest(actionDigest);
    const { bytes } = await this.client.request(
      "GET",
      this.client.acPath(actionDigest),
      { context: "ac" },
    );
    return bytes;
  }

  /**
   * Store `ActionResult` bytes under an action digest. Create-only /
   * content-immutable server-side: a divergent overwrite is rejected 409.
   * Returns the action digest.
   * @throws {ConflictError} 409 — an immutable entry already exists.
   */
  async put(actionDigest: string, result: Uint8Array): Promise<string> {
    this.client.assertDigest(actionDigest);
    await this.client.request("PUT", this.client.acPath(actionDigest), {
      body: result,
      contentType: "application/octet-stream",
      context: "ac",
    });
    return actionDigest;
  }
}

function decode(bytes: Uint8Array): string {
  try {
    return new TextDecoder().decode(bytes);
  } catch {
    return "";
  }
}
