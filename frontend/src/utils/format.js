export function safeHostname(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return url;
  }
}

export function formatDate(value) {
  if (!value) return "Unknown date";
  return new Date(value).toLocaleString();
}
