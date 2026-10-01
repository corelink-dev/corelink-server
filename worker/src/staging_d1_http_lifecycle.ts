import { STAGING_D1_HTTP_CLEANUP_MS, STAGING_D1_HTTP_EXECUTE_MS } from "./staging_d1_http_contract.js";

/** A timeout fences continuations; it does not cancel the submitted operation. */
export class StagingD1HttpLifecycle {
  private readonly pending = new Set<Promise<unknown>>();
  readonly startedAt: number;
  readonly executeDeadline: number;
  private cleanupDeadline: number | undefined;
  private stopped = false;

  constructor(private readonly now: () => number, private readonly expires: number, executeDeadline = Infinity) {
    this.startedAt = now();
    this.executeDeadline = Math.min(this.startedAt + STAGING_D1_HTTP_EXECUTE_MS, expires, executeDeadline);
  }

  check(): void {
    if (this.stopped || this.now() >= this.executeDeadline) {
      this.stopped = true;
      throw new Error("http proof execution stopped");
    }
  }

  /** Stop future execution without claiming cancellation or quiescence. */
  halt(): void { this.stopped = true; }

  get settled(): boolean { return this.pending.size === 0; }

  private async bounded<T>(operation: () => Promise<T>, deadline: number): Promise<T> {
    if (this.now() >= deadline) throw new Error("http proof deadline");
    const submitted = Promise.resolve().then(operation);
    this.pending.add(submitted);
    void submitted.then(() => this.pending.delete(submitted), () => this.pending.delete(submitted));
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      const result = await Promise.race([submitted, new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => reject(new Error("http proof deadline")), deadline - this.now());
      })]);
      if (this.now() >= deadline) throw new Error("http proof deadline");
      return result;
    } finally { if (timer !== undefined) clearTimeout(timer); }
  }

  async run<T>(operation: () => Promise<T>): Promise<T> {
    this.check();
    try {
      const result = await this.bounded(() => { this.check(); return operation(); }, this.executeDeadline);
      this.check();
      return result;
    } catch {
      this.stopped = true;
      throw new Error("http proof execution stopped");
    }
  }

  /** One cumulative cleanup budget, including waiting for uncancellable work. */
  beginCleanup(): void {
    this.stopped = true;
    this.cleanupDeadline ??= Math.min(this.now() + STAGING_D1_HTTP_CLEANUP_MS, this.expires,
      this.startedAt + STAGING_D1_HTTP_EXECUTE_MS + STAGING_D1_HTTP_CLEANUP_MS);
  }

  get completionDeadline(): number {
    if (this.cleanupDeadline === undefined) throw new Error("http proof cleanup not started");
    return this.cleanupDeadline;
  }

  checkCleanup(): void {
    if (this.cleanupDeadline === undefined || this.now() >= this.cleanupDeadline) throw new Error("http proof cleanup stopped");
  }

  async quiesce(): Promise<void> {
    this.beginCleanup();
    const outstanding = [...this.pending];
    if (outstanding.length) await this.bounded(async () => {
      await Promise.allSettled(outstanding);
    }, this.cleanupDeadline!);
    if (!this.settled) throw new Error("http proof operation pending");
  }

  async cleanup<T>(operation: () => Promise<T>): Promise<T> {
    this.beginCleanup();
    if (!this.settled) throw new Error("http proof operation pending");
    return this.bounded(operation, this.cleanupDeadline!);
  }

  /** Only durable status writes may precede quiescence; never provider cleanup. */
  async record<T>(operation: () => Promise<T>): Promise<T> {
    this.beginCleanup();
    return this.bounded(operation, this.cleanupDeadline!);
  }
}
