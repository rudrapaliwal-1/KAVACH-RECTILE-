function getApiBase(): string {
  // If explicitly specified in .env, use it
  if (import.meta.env.VITE_API_BASE_URL) {
    return import.meta.env.VITE_API_BASE_URL.replace(/\/$/, "");
  }
  // In the browser, use relative paths so Vite's proxy handles it same-origin.
  // This guarantees cookies (SameSite=Lax) are ALWAYS attached regardless of whether
  // the user navigates via localhost:5173 or 127.0.0.1:5173.
  if (typeof window !== "undefined") {
    return "";
  }
  return "http://127.0.0.1:8000";
}

const API_BASE = getApiBase();
const TIMEOUT_MS = 15_000;

let csrfToken =
  (typeof window !== "undefined" ? sessionStorage.getItem("sentinel_csrf_token") || "" : "") ||
  (import.meta.hot?.data.csrfToken as string | undefined) ||
  "";

if (import.meta.hot) {
  import.meta.hot.dispose(data => {
    data.csrfToken = csrfToken;
  });
}

export function setCsrfToken(token: string) {
  csrfToken = token;
  if (typeof window !== "undefined") {
    if (token) {
      sessionStorage.setItem("sentinel_csrf_token", token);
    } else {
      sessionStorage.removeItem("sentinel_csrf_token");
    }
  }
}

export function getCsrfToken() {
  return csrfToken;
}

export async function ensureCsrfToken(): Promise<string> {
  if (csrfToken) return csrfToken;
  try {
    const res = await fetch(`${API_BASE}/api/auth/me`, { credentials: "include" });
    if (res.ok) {
      const data = await res.json();
      if (data?.csrf_token) {
        setCsrfToken(data.csrf_token);
        return data.csrf_token;
      }
    }
  } catch {}
  return csrfToken;
}

export class ApiError extends Error {
  status: number;
  payload: unknown;
  constructor(message: string, status = 0, payload?: unknown) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.payload = payload;
  }
}

export async function request<T>(path: string, init: RequestInit = {}, timeoutMs = TIMEOUT_MS): Promise<T> {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), timeoutMs);
  try {
    const method = (init.method || "GET").toUpperCase();
    const url = path.startsWith("http") ? path : `${API_BASE}${path}`;

    // Ensure we have a CSRF token before performing any mutating request
    if (method !== "GET" && method !== "HEAD" && !csrfToken) {
      await ensureCsrfToken();
    }

    const response = await fetch(url, {
      ...init,
      credentials: "include",
      signal: controller.signal,
      headers: {
        Accept: "application/json",
        ...(init.body && typeof init.body === "string" ? { "Content-Type": "application/json" } : {}),
        ...(method !== "GET" && method !== "HEAD" && csrfToken ? { "X-CSRF-Token": csrfToken } : {}),
        ...init.headers,
      },
    });

    const raw = await response.text();
    let body: unknown = undefined;
    if (raw) {
      try {
        body = JSON.parse(raw);
      } catch {
        body = raw;
      }
    }

    if (!response.ok) {
      const record = body && typeof body === "object" ? (body as Record<string, unknown>) : {};

      // If CSRF token was rejected (missing/stale/rotated), refresh it and retry once
      if (
        response.status === 403 &&
        (record.code === "CSRF_FAILED" || String(record.detail || "").includes("CSRF"))
      ) {
        csrfToken = "";
        const freshToken = await ensureCsrfToken();
        if (freshToken) {
          const retryRes = await fetch(url, {
            ...init,
            credentials: "include",
            signal: controller.signal,
            headers: {
              Accept: "application/json",
              ...(init.body && typeof init.body === "string" ? { "Content-Type": "application/json" } : {}),
              "X-CSRF-Token": freshToken,
              ...init.headers,
            },
          });
          const retryRaw = await retryRes.text();
          let retryBody: unknown = undefined;
          if (retryRaw) {
            try {
              retryBody = JSON.parse(retryRaw);
            } catch {
              retryBody = retryRaw;
            }
          }
          if (retryRes.ok) {
            return retryBody as T;
          }
        }
      }

      if (response.status === 401 && !path.startsWith("/api/auth/")) {
        window.dispatchEvent(new Event("sentinel-session-expired"));
      }
      throw new ApiError(
        String(record.detail ?? record.message ?? record.error ?? `Request failed (${response.status})`),
        response.status,
        body
      );
    }
    return body as T;
  } catch (error) {
    if (error instanceof ApiError) throw error;
    if (error instanceof DOMException && error.name === "AbortError") {
      throw new ApiError(`Request timed out after ${Math.round(timeoutMs / 1000)} seconds.`);
    }
    throw new ApiError("Cannot reach the KAVACH-X API. Check the backend URL and availability.");
  } finally {
    window.clearTimeout(timeout);
  }
}

export const apiBaseUrl = API_BASE || (typeof window !== "undefined" ? window.location.origin : "http://127.0.0.1:8000");
