import { API } from "../constants";
import { formatApiError } from "../utils/errors";

/** OOP wrapper for all HTTP calls to the backend API. */
export class ApiClient {
  constructor(baseUrl = API) {
    this.baseUrl = baseUrl;
  }

  async request(path, { token, ...options } = {}) {
    const headers = new Headers(options.headers || {});

    if (!(options.body instanceof FormData)) {
      headers.set("Content-Type", "application/json");
    }
    if (token) {
      headers.set("Authorization", `Bearer ${token}`);
    }

    const response = await fetch(`${this.baseUrl}${path}`, { ...options, headers });
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
}

export const apiClient = new ApiClient();
