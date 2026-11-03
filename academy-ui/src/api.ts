// Same-origin API client, ported from the existing Academy script: bounded waits and a clear disconnected state.
export const FETCH_MS = 20000;
export type ApiResult<T = any> = { status: number; ok: boolean; data: T };

export async function api<T = any>(path: string, options: RequestInit = {}): Promise<ApiResult<T>> {
  const ctl = new AbortController();
  const timer = window.setTimeout(() => ctl.abort(), FETCH_MS);
  try {
    const r = await window.fetch(path, { ...options, signal: ctl.signal });
    const data = await r.json().catch(() => httpProblem(r.status));
    return { status: r.status, ok: r.ok, data };
  } catch (err) {
    const aborted = err instanceof DOMException && err.name === "AbortError";
    return { status: 0, ok: false, data: { error: aborted ? "timeout" : "disconnected", detail: aborted ? `No answer within ${FETCH_MS / 1000} seconds.` : "The Attack Service could not be reached." } as T };
  } finally {
    window.clearTimeout(timer);
  }
}

/** A body that is not JSON comes from the gateway or a proxy, not from the lab's own API. Name what the status means instead of blaming the format. */
export function httpProblem(status: number): { error: string; detail: string } {
  if (status === 401) return { error: "unauthorized", detail: "You are not signed in, or your sign-in expired. Reload the page and sign in again. Nothing ran." };
  if (status === 403) return { error: "forbidden", detail: "The gateway refused this action. Starting runs and live searches needs the operator role; reading, recorded evidence and results do not. Sign in as the operator to run it. Nothing ran." };
  if (status === 429) return { error: "rate_limited", detail: "Too many launches or searches in a short time. Wait a few seconds and try again. Nothing ran." };
  if (status === 421) return { error: "wrong_host", detail: "The address in the browser is not the lab's configured host name and port. Open the Academy at the address the installer printed." };
  if (status >= 500) return { error: "gateway_error", detail: `The gateway or a service behind it failed (HTTP ${status}) and sent no details.` };
  return { error: "non_json", detail: `The server sent a reply that is not JSON (HTTP ${status}).` };
}

export const post = <T = any>(path: string, body: unknown) =>
  api<T>(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });

export function problemText(res: ApiResult): string {
  const e = res.data?.error;
  if (e === "disconnected") return "Disconnected: the Attack Service cannot be reached. Check that the lab is running, then retry.";
  if (e === "timeout") return "Timed out: no answer in time. The run may still be working; retry in a moment.";
  if (e === "acmebank_unreachable") return "AcmeBank (the Loan Desk) cannot be reached from the Attack Service. Start or restart AcmeBank, then retry.";
  if (e === "acmebank_timeout") return "AcmeBank did not answer in time. Retry in a moment.";
  return res.data?.detail || res.data?.error || `Unexpected response (HTTP ${res.status}).`;
}
