import { TacticalError, isRetryableTactical } from "../tactical/client.ts";
import { PatchGateError } from "../pg-client.ts";
import { AbortedError } from "../util/backoff.ts";

/** A job failure with an explicit retry classification (sent to PatchGate as JobResult.retryable). */
export class JobError extends Error {
  constructor(
    message: string,
    readonly retryable: boolean,
    /**
     * The install MAY have run (timeout / lost connection / gateway error while the script was running).
     * Never retryable: PatchGate confirms via inventory instead of failing or re-queueing (no second installer).
     */
    readonly outcomeUnknown = false,
  ) {
    super(message);
    this.name = "JobError";
  }
}

export const permanent = (msg: string): JobError => new JobError(msg, false);
export const transient = (msg: string): JobError => new JobError(msg, true);
export const outcomeUnknown = (msg: string): JobError => new JobError(msg, false, true);

/** Map any thrown value to a JobError (unknown errors are permanent: never guess "safe to retry"). */
export function toJobError(err: unknown): JobError {
  if (err instanceof JobError) return err;
  if (err instanceof TacticalError) {
    const detail = err.detail ? `: ${err.detail}` : "";
    return new JobError(`${err.message}${detail}`, isRetryableTactical(err));
  }
  if (err instanceof PatchGateError) return new JobError(err.message, err.retryable);
  if (err instanceof AbortedError) return new JobError("connector shutting down", true);
  const msg = err instanceof Error ? err.message : "unknown error";
  return new JobError(msg, false);
}
