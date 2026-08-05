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

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  const token = getToken();
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
  if (res.status === 401) {
    setToken("");
    if (!location.hash.includes("/login")) location.assign("#/login");
    throw new ApiError(401, "session expired — sign in again");
  }
  if (res.status === 204) return undefined as T;
  const text = await res.text();
  let data: unknown = undefined;
  try { data = text ? JSON.parse(text) : undefined; } catch { data = text; }
  if (!res.ok) {
    const detail = (data as { detail?: unknown })?.detail;
    const msg = typeof detail === "string" ? detail
      : Array.isArray(detail) ? detail.map((d: { msg?: string }) => d.msg).join("; ")
      : `request failed (${res.status})`;
    throw new ApiError(res.status, msg, data);
  }
  return data as T;
}

export const api = {
  get: <T>(path: string) => request<T>(path),
  post: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: "POST", body: body === undefined ? undefined : JSON.stringify(body) }),
  put: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: "PUT", body: body === undefined ? undefined : JSON.stringify(body) }),
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
    const t = await api.form<{ access_token: string }>("/admin/token", { username, password });
    setToken(t.access_token);
  },
  logout(): void { setToken(""); },
};
