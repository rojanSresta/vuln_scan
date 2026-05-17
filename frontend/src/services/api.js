import { API } from "../constants";
import { formatApiError } from "../utils/errors";

export async function apiFetch(path, { token, ...options } = {}) {
  const headers = new Headers(options.headers || {});

  if (!(options.body instanceof FormData)) {
    headers.set("Content-Type", "application/json");
  }
  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }

  const response = await fetch(`${API}${path}`, { ...options, headers });
  if (!response.ok) {
    let detail = "Request failed";
    try {
      const payload = await response.json();
      detail = formatApiError(payload.detail, detail);
    } catch {
      detail = response.statusText || detail;
    }
    throw new Error(detail);
  }
  return response;
}
