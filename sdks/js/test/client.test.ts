import { afterEach, describe, expect, it, vi } from "vitest";
import {
  ActionCacheMiss,
  AuthError,
  ConflictError,
  CoreLinkClient,
  CoreLinkError,
  DigestMismatchError,
  ForbiddenError,
  GoneError,
  NotFoundError,
  QuotaError,
  blake3Hex,
  isCanonicalDigest,
} from "../src/index.js";

/** A recording fetch stub that dispatches to a per-call handler. */
function mockFetch(
  handler: (url: string, init: RequestInit) => Response | Promise<Response>,
) {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  const fn = (async (url: unknown, init: unknown) => {
    calls.push({ url: String(url), init: (init ?? {}) as RequestInit });
    return handler(String(url), (init ?? {}) as RequestInit);
  }) as unknown as typeof fetch;
  return Object.assign(fn, { calls });
}

const PAT = "corelink_dev_t_test.aaa.bbb";
const TENANT = "acme-corp";

function client(fetchImpl: typeof fetch, overrides = {}) {
  return new CoreLinkClient({
    pat: PAT,
    tenantId: TENANT,
    fetch: fetchImpl,
    retry: { maxAttempts: 3, baseDelayMs: 1, maxDelayMs: 2 },
    ...overrides,
  });
}

afterEach(() => {
  vi.restoreAllMocks();
  delete process.env.CORELINK_PAT;
});

describe("digest helpers", () => {
  it("computes the canonical BLAKE3 empty-input vector", () => {
    // Well-known BLAKE3-256 hash of the empty input.
    expect(blake3Hex(new Uint8Array())).toBe(
      "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
    );
  });

  it("validates canonical digests (64 lowercase hex)", () => {
    expect(isCanonicalDigest("a".repeat(64))).toBe(true);
    expect(isCanonicalDigest("A".repeat(64))).toBe(false); // uppercase rejected
    expect(isCanonicalDigest("a".repeat(63))).toBe(false);
    expect(isCanonicalDigest("g".repeat(64))).toBe(false);
  });
});

describe("construction", () => {
  it("throws without a PAT", () => {
    expect(() => new CoreLinkClient({ tenantId: TENANT } as never)).toThrow(
      CoreLinkError,
    );
  });

  it("falls back to CORELINK_PAT env", async () => {
    process.env.CORELINK_PAT = PAT;
    const f = mockFetch(() => new Response(new Uint8Array(), { status: 201 }));
    const c = new CoreLinkClient({ tenantId: TENANT, fetch: f });
    await c.put(new Uint8Array([1, 2, 3]));
    const auth = f.calls[0]!.init.headers as Record<string, string>;
    expect(auth.authorization).toBe(`Bearer ${PAT}`);
  });

  it("requires a tenantId", () => {
    expect(() => new CoreLinkClient({ pat: PAT } as never)).toThrow(CoreLinkError);
  });

  it.each([
    ["normal trailing slashes", "https://api.example///", "https://api.example"],
    ["no trailing slash", "https://api.example/path", "https://api.example/path"],
    ["all slashes", "////", ""],
    ["empty", "", ""],
    ["interior slash run", "https://api.example/a//b///", "https://api.example/a//b"],
    [
      "long slash run followed by non-slash",
      `https://api.example${"/".repeat(50_000)}x`,
      `https://api.example${"/".repeat(50_000)}x`,
    ],
  ])("normalizes the request base without changing %s", async (_label, baseUrl, expectedBase) => {
    const data = new TextEncoder().encode("normalization oracle");
    const digest = blake3Hex(data);
    const f = mockFetch(() => new Response(digest, { status: 201 }));
    await client(f, { baseUrl }).put(data);
    expect(f.calls[0]!.url).toBe(`${expectedBase}/v1/cas/${TENANT}/${digest}`);
  });

  it("_clientVerifyEnabled defaults true; false logs a warning", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const f = mockFetch(() => new Response(null, { status: 200 }));
    expect(client(f)._clientVerifyEnabled).toBe(true);
    expect(warn).not.toHaveBeenCalled();
    const c2 = client(f, { clientVerify: false });
    expect(c2._clientVerifyEnabled).toBe(false);
    expect(warn).toHaveBeenCalledOnce();
  });
});

describe("put", () => {
  it("PUTs to /v1/cas/{tenant}/{blake3} and returns the digest", async () => {
    const data = new TextEncoder().encode("hello world");
    const expected = blake3Hex(data);
    const f = mockFetch(() => new Response(expected, { status: 201 }));
    const digest = await client(f).put(data);
    expect(digest).toBe(expected);
    const call = f.calls[0]!;
    expect(call.init.method).toBe("PUT");
    expect(call.url).toBe(
      `https://corelink-api.humangr.com/v1/cas/${TENANT}/${expected}`,
    );
  });

  it("honors a matching expectedDigest and rejects a mismatch", async () => {
    const data = new Uint8Array([9, 9, 9]);
    const good = blake3Hex(data);
    const f = mockFetch(() => new Response(good, { status: 201 }));
    await expect(client(f).put(data, { expectedDigest: good })).resolves.toBe(good);
    await expect(
      client(f).put(data, { expectedDigest: "b".repeat(64) }),
    ).rejects.toBeInstanceOf(DigestMismatchError);
  });

  it("maps 422 (server hash mismatch) to DigestMismatchError", async () => {
    const f = mockFetch(() => new Response("content hash mismatch", { status: 422 }));
    await expect(client(f).put(new Uint8Array([1]))).rejects.toBeInstanceOf(
      DigestMismatchError,
    );
  });
});

describe("get", () => {
  it("returns bytes and verifies BLAKE3 by default", async () => {
    const data = new TextEncoder().encode("payload");
    const digest = blake3Hex(data);
    const f = mockFetch(() => new Response(data, { status: 200 }));
    const out = await client(f).get(digest);
    expect(new TextDecoder().decode(out)).toBe("payload");
  });

  it("throws DigestMismatchError when returned bytes are tampered", async () => {
    const data = new TextEncoder().encode("payload");
    const digest = blake3Hex(data);
    const f = mockFetch(() => new Response("TAMPERED", { status: 200 }));
    await expect(client(f).get(digest)).rejects.toBeInstanceOf(DigestMismatchError);
  });

  it("skips verify when verify:false", async () => {
    const data = new TextEncoder().encode("payload");
    const digest = blake3Hex(data);
    const f = mockFetch(() => new Response("TAMPERED", { status: 200 }));
    const out = await client(f).get(digest, { verify: false });
    expect(new TextDecoder().decode(out)).toBe("TAMPERED");
  });

  it("rejects a non-canonical digest before any request", async () => {
    const f = mockFetch(() => new Response(null, { status: 200 }));
    await expect(client(f).get("nope")).rejects.toBeInstanceOf(CoreLinkError);
    expect(f.calls.length).toBe(0);
  });

  it("maps 404 -> NotFoundError and 410 -> GoneError", async () => {
    const digest = "c".repeat(64);
    const f404 = mockFetch(() => new Response("not found", { status: 404 }));
    await expect(client(f404).get(digest)).rejects.toBeInstanceOf(NotFoundError);
    const f410 = mockFetch(() => new Response("erased", { status: 410 }));
    await expect(client(f410).get(digest)).rejects.toBeInstanceOf(GoneError);
  });
});

describe("stat", () => {
  /** Records how many body bytes the stub "server" hands to the client. */
  function countingFetch(
    respond: () => Response,
  ): ReturnType<typeof mockFetch> & { bytesServed: () => number } {
    let served = 0;
    const f = mockFetch(() => {
      const res = respond();
      // Simulate the wire: count whatever payload the response carries.
      res.arrayBuffer().then((ab) => {
        served += ab.byteLength;
      });
      return res;
    });
    return Object.assign(f, { bytesServed: () => served });
  }

  it("issues a HEAD (not GET) with no request body, like the Python SDK", async () => {
    const data = new Uint8Array(1234);
    const digest = blake3Hex(data);
    const f = mockFetch((url, init) => {
      expect(init.method).toBe("HEAD");
      expect(init.body).toBeUndefined();
      expect(url).toBe(
        `https://corelink-api.humangr.com/v1/cas/${TENANT}/${digest}`,
      );
      return new Response(null, {
        status: 200,
        headers: { "content-length": String(data.byteLength) },
      });
    });
    await client(f).stat(digest);
    expect(f.calls.length).toBe(1);
  });

  it("does NOT transfer the blob body — size comes from Content-Length", async () => {
    const data = new Uint8Array(1234);
    const digest = blake3Hex(data);
    // A real HEAD response has an empty body; only the header carries the size.
    const f = countingFetch(() =>
      new Response(null, {
        status: 200,
        headers: { "content-length": String(data.byteLength) },
      }),
    );
    await expect(client(f).stat(digest)).resolves.toEqual({
      digest,
      exists: true,
      sizeBytes: 1234,
    });
    expect(f.bytesServed()).toBe(0);
  });

  it("reports absent on 404/410", async () => {
    const digest = "d".repeat(64);
    const f404 = mockFetch(() => new Response("not found", { status: 404 }));
    expect(await client(f404).stat(digest)).toEqual({
      digest,
      exists: false,
      sizeBytes: 0,
    });
    const f410 = mockFetch(() => new Response("erased", { status: 410 }));
    expect(await client(f410).stat(digest)).toEqual({
      digest,
      exists: false,
      sizeBytes: 0,
    });
  });

  it("still maps unexpected statuses through the normal error path", async () => {
    const digest = "d".repeat(64);
    const f = mockFetch(() => new Response("who are you", { status: 401 }));
    await expect(client(f).stat(digest)).rejects.toBeInstanceOf(AuthError);
  });
});

describe("action cache", () => {
  it("get returns opaque bytes; 404 -> ActionCacheMiss", async () => {
    const digest = "e".repeat(64);
    const payload = new Uint8Array([1, 2, 3, 4]);
    const hit = mockFetch(() => new Response(payload, { status: 200 }));
    const c = client(hit);
    expect(Array.from(await c.actionCache.get(digest))).toEqual([1, 2, 3, 4]);
    expect(hit.calls[0]!.url).toBe(
      `https://corelink-api.humangr.com/v1/ac/${TENANT}/${digest}`,
    );
    const miss = mockFetch(() => new Response("ac miss", { status: 404 }));
    await expect(client(miss).actionCache.get(digest)).rejects.toBeInstanceOf(
      ActionCacheMiss,
    );
  });

  it("put returns the action digest; 409 -> ConflictError", async () => {
    const digest = "f".repeat(64);
    const ok = mockFetch(() => new Response(digest, { status: 201 }));
    await expect(
      client(ok).actionCache.put(digest, new Uint8Array([5])),
    ).resolves.toBe(digest);
    const conflict = mockFetch(() => new Response("divergent body", { status: 409 }));
    await expect(
      client(conflict).actionCache.put(digest, new Uint8Array([5])),
    ).rejects.toBeInstanceOf(ConflictError);
  });
});

describe("error mapping", () => {
  const digest = "a".repeat(64);
  const cases: Array<[number, unknown]> = [
    [401, AuthError],
    [402, QuotaError],
    [403, ForbiddenError],
  ];
  for (const [status, cls] of cases) {
    it(`maps ${status}`, async () => {
      const f = mockFetch(() => new Response("x", { status }));
      await expect(client(f).get(digest)).rejects.toBeInstanceOf(cls as never);
    });
  }
});

describe("retry", () => {
  it("retries a 429 then succeeds", async () => {
    const data = new TextEncoder().encode("ok");
    const digest = blake3Hex(data);
    let n = 0;
    const f = mockFetch(() => {
      n++;
      return n === 1
        ? new Response("slow down", { status: 429 })
        : new Response(data, { status: 200 });
    });
    const out = await client(f).get(digest);
    expect(new TextDecoder().decode(out)).toBe("ok");
    expect(f.calls.length).toBe(2);
  });

  it("gives up after maxAttempts and throws the mapped error", async () => {
    const digest = "a".repeat(64);
    const f = mockFetch(() => new Response("slow down", { status: 429 }));
    await expect(client(f).get(digest)).rejects.toBeInstanceOf(CoreLinkError);
    expect(f.calls.length).toBe(3);
  });
});
