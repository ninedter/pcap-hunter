export function formatTrafficBytes(value) {
  const bytes = Math.max(0, Number(value) || 0);
  if (bytes === 0) return "0 B";
  if (bytes < 1024) return `${Math.floor(bytes)} B`;
  if (bytes >= 1_048_576) return `${(bytes / 1_048_576).toFixed(1)} MiB`;
  return `${(bytes / 1024).toFixed(1)} KiB`;
}

function normalizedSearch(search = "") {
  if (!search) return "";
  return search.startsWith("?") ? search : `?${search}`;
}

export function buildScreenRoute(screen, search = "") {
  return `${screen === "analyze" ? "/" : `/${screen}`}${normalizedSearch(search)}`;
}

export function buildDashboardViewRoute(target, search = "") {
  return `/dashboard${normalizedSearch(search)}#${target}`;
}

export function isCurrentRoute(pathname = "", search = "", target = "") {
  return `${pathname}${normalizedSearch(search)}` === target;
}

export function filterDashboardMapFlows(flows, { query = "", protocol = "All", time = "" } = {}) {
  const normalizedQuery = query.trim().toLowerCase();
  const hasProtocolFilter = protocol && protocol !== "All";
  const hasTimeFilter = Boolean(time);

  return (flows || []).flatMap((flow) => {
    const searchable = `${flow.ip} ${flow.city} ${flow.country} ${flow.continent || ""}`.toLowerCase();
    if (normalizedQuery && !searchable.includes(normalizedQuery)) return [];

    if (!hasProtocolFilter && !hasTimeFilter) return [flow];

    const slices = Array.isArray(flow.traffic_slices) ? flow.traffic_slices : [];
    if (!slices.length) {
      if (hasTimeFilter || (hasProtocolFilter && !flow.protocols?.includes(protocol))) return [];
      return [flow];
    }

    const matchingSlices = slices.filter((slice) => (
      (!hasProtocolFilter || slice.protocol === protocol)
      && (!hasTimeFilter || slice.time === time)
    ));
    if (!matchingSlices.length) return [];

    const packets = matchingSlices.reduce((sum, slice) => sum + (Number(slice.packets) || 0), 0);
    const byteCount = matchingSlices.reduce((sum, slice) => sum + (Number(slice.bytes) || 0), 0);
    const protocols = [...new Set(matchingSlices.map((slice) => slice.protocol).filter(Boolean))].sort();

    return [{
      ...flow,
      packets,
      byte_count: byteCount,
      bytes: formatTrafficBytes(byteCount),
      protocols,
    }];
  });
}

const DATED_TIME_LABEL = /^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}:\d{2})/;

/** True when timeline labels carry a date (the capture spans more than one UTC day). */
export function isMultiDayTimeline(rows) {
  return (rows || []).some((row) => DATED_TIME_LABEL.test(String(row?.time || "")));
}

/**
 * Axis tick text for a timeline bucket label. Single-day labels ("12:02") are
 * unchanged; dated labels ("2026-03-01 12:02") drop the year so ticks stay
 * short. Display only: selection and map filtering use the full label.
 */
export function formatTimelineTick(label) {
  const text = String(label ?? "");
  const match = DATED_TIME_LABEL.exec(text);
  return match ? `${match[2]}-${match[3]} ${match[4]}` : text;
}
