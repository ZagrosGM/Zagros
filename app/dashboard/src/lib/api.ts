import type { Key as I18nKey } from "./i18n";
// API client — one wrapper for the legacy admin API and the Zagros admin
// surface; token handling, 401 recovery, and error shaping live here only.

const TOKEN_KEY = "zagros.token";
// API root: env at build time (dev), "/api" in the shipped bundle.
// Call sites pass paths WITHOUT the /api prefix (e.g. "/users", "/zagros/cores").
const BASE = (import.meta.env.VITE_BASE_API || "/api/").replace(/\/$/, "");

export function getToken(): string {
  try { return localStorage.getItem(TOKEN_KEY) || ""; } catch { return ""; }
}
export function setToken(token: string) {
  try {
    if (token) localStorage.setItem(TOKEN_KEY, token);
    else localStorage.removeItem(TOKEN_KEY);
  } catch { /* private mode — session only */ }
}

export class ApiError extends Error {
  constructor(public status: number, message: string, public payload?: unknown) {
    super(message);
  }
}

/** The sign-in call itself: a 401 here means WRONG CREDENTIALS, never an
 *  expired session. */
const LOGIN_PATH = "/admin/token";

/** Session-generation counter. Bumped on every sign-in and sign-out so a
 *  response that belongs to an OLDER session (a background poller fired with
 *  a stale token a moment before the operator signed in) can never clear the
 *  fresh token or redirect the shell back to /login. */
let sessionGeneration = 0;
export function bumpSession(): void { sessionGeneration += 1; }

function detailMessage(data: unknown, status: number): string {
  const detail = (data as { detail?: unknown })?.detail;
  return typeof detail === "string" ? detail
    : Array.isArray(detail) ? detail.map((d: { msg?: string }) => d.msg).join("; ")
    : `request failed (${status})`;
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  const token = getToken();
  const generation = sessionGeneration;
  if (token) headers.set("Authorization", `Bearer ${token}`);
  if (init.body && !headers.has("Content-Type") && !(init.body instanceof FormData)) {
    headers.set("Content-Type", "application/json");
  }
  let res: Response;
  try {
    res = await fetch(`${BASE}${path}`, { ...init, headers });
  } catch {
    throw new ApiError(0, "network error — the panel is unreachable");
  }
  if (res.status === 204) return undefined as T;
  const text = await res.text();
  let data: unknown = undefined;
  try { data = text ? JSON.parse(text) : undefined; } catch { data = text; }
  if (res.status === 401) {
    if (path === LOGIN_PATH) {
      // Bad username/password (or an expired admin account) — the server's
      // detail says which; never mistake it for a dead session.
      throw new ApiError(401, detailMessage(data, 401), data);
    }
    // Only the CURRENT session may be declared dead: a late reply to a
    // request sent with a previous token must not log the operator out.
    if (generation === sessionGeneration && token && getToken() === token) {
      setToken("");
      bumpSession();
      if (!location.hash.includes("/login")) location.assign("#/login");
      throw new ApiError(401, "session expired — sign in again");
    }
    throw new ApiError(401, detailMessage(data, 401), data);
  }
  if (!res.ok) throw new ApiError(res.status, detailMessage(data, res.status), data);
  return data as T;
}

/** Download a file the API protects with a bearer token.
 *
 *  `window.open()` cannot send the Authorization header, so archives are
 *  fetched here and handed to the browser as a blob. */
export async function download(path: string, filename: string): Promise<void> {
  const headers = new Headers();
  const token = getToken();
  if (token) headers.set("Authorization", `Bearer ${token}`);
  const res = await fetch(`${BASE}${path}`, { headers });
  if (!res.ok) throw new ApiError(res.status, `download failed (${res.status})`);
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

export const api = {
  get: <T>(path: string) => request<T>(path),
  post: <T>(path: string, body?: unknown) =>
    request<T>(path, {
      method: "POST",
      body: body === undefined ? undefined : (body instanceof FormData ? body : JSON.stringify(body)),
    }),
  put: <T>(path: string, body?: unknown) =>
    request<T>(path, {
      method: "PUT",
      body: body === undefined ? undefined : (body instanceof FormData ? body : JSON.stringify(body)),
    }),
  delete: <T>(path: string) => request<T>(path, { method: "DELETE" }),
  form: <T>(path: string, form: Record<string, string>) =>
    request<T>(path, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams(form).toString(),
    }),
};

export const auth = {
  async login(username: string, password: string): Promise<void> {
    // A stale token from a previous session must not ride along on the
    // sign-in request, and nothing issued before this moment may touch the
    // new session (see sessionGeneration).
    setToken("");
    bumpSession();
    const t = await api.form<{ access_token: string }>(LOGIN_PATH, { username, password });
    setToken(t.access_token);
    bumpSession();
  },
  logout(): void { setToken(""); bumpSession(); },
};

/** Human-readable reason a Zagros admin panel query failed.
 *
 *  A 403 really is a permission problem; a 503 means the platform runtime is
 *  not available (typically the database was still starting). Reporting every
 *  failure as "requires sudo admin" sent operators hunting for the wrong bug. */
export function adminQueryErrorKey(error: unknown): I18nKey {
  const status = error instanceof ApiError ? error.status : undefined;
  if (status === 403) return "requires sudo admin";
  if (status === 503) return "the Zagros platform runtime is unavailable — check that the database is running";
  if (status === 0) return "network error — the panel is unreachable";
  return "could not load this section — see the panel logs";
}
