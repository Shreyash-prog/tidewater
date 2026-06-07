import type { DashboardConfig } from "@/api/types";

const TOKEN_KEY = "tidewater_token";

let configPromise: Promise<DashboardConfig> | null = null;

/**
 * Discover the API base URL at runtime from /config.json (deployed alongside the
 * SPA assets). This keeps the built artifact environment-agnostic — the same
 * build runs against any deployed stack, with no build-time URL injection.
 */
function loadConfig(): Promise<DashboardConfig> {
  if (!configPromise) {
    configPromise = fetch("/config.json")
      .then((r) => {
        if (!r.ok) throw new Error(`config.json fetch failed: ${r.status}`);
        return r.json() as Promise<DashboardConfig>;
      })
      .catch((err: unknown) => {
        // Defensive: fall back to relative URLs. The error then surfaces as a
        // 404/500 on the next API call, which is more diagnostic than swallowing it.
        console.error("Failed to load /config.json:", err);
        return { apiBaseUrl: "" };
      });
  }
  return configPromise;
}

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string): void {
  localStorage.setItem(TOKEN_KEY, token);
}

export function clearToken(): void {
  localStorage.removeItem(TOKEN_KEY);
}

export async function apiGet<T>(path: string): Promise<T> {
  const { apiBaseUrl } = await loadConfig();
  const token = getToken();
  if (!token) throw new ApiError(401, "no token");
  const resp = await fetch(`${apiBaseUrl}${path}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (resp.status === 401 || resp.status === 403) {
    clearToken();
    window.location.reload();
    throw new ApiError(resp.status, "invalid token");
  }
  if (!resp.ok) {
    throw new ApiError(resp.status, await resp.text());
  }
  return (await resp.json()) as T;
}
