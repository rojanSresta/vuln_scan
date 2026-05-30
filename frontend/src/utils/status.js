const STATUS_CLASSES = {
  queued: "bg-slate-100 text-slate-700",
  spidering: "bg-sky-100 text-sky-800",
  scanning: "bg-sky-100 text-sky-800",
  done: "bg-emerald-100 text-emerald-800",
  error: "bg-red-100 text-red-800",
  cancelled: "bg-amber-100 text-amber-900",
};

export function statusBadgeClass(status) {
  return STATUS_CLASSES[status] || "bg-slate-100 text-slate-700";
}
