import { apiClient } from "./api_client";

/** Fetch helper used by hooks (delegates to ApiClient). */
export async function apiFetch(path, options = {}) {
  return apiClient.request(path, options);
}
