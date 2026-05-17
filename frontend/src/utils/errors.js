export function formatApiError(detail, fallback = "Request failed") {
  if (!detail) return fallback;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    return detail
      .map((item) => {
        if (typeof item === "string") return item;
        if (item && typeof item === "object" && item.msg) {
          const field = Array.isArray(item.loc) ? item.loc.filter((part) => part !== "body").join(".") : "";
          return field ? `${field}: ${item.msg}` : item.msg;
        }
        return String(item);
      })
      .join("; ");
  }
  if (typeof detail === "object" && detail.msg) return detail.msg;
  return fallback;
}
