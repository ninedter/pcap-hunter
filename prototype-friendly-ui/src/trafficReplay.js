export const getReplayLane = (scope) => {
  const value = String(scope || "").toLowerCase();
  if (/(multicast|broadcast|special|group)/.test(value)) return "special";
  if (/(external|public|internet|remote)/.test(value)) return "external";
  if (/(internal|private|local)/.test(value)) return "internal";
  return "special";
};

const dateValue = (value) => {
  if (value === null || value === undefined || value === "") return null;
  if (typeof value === "number" && Number.isFinite(value)) return value * 1000;
  if (typeof value === "string" && /^\d+(?:\.\d+)?$/.test(value.trim())) return Number(value) * 1000;
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? null : parsed;
};

export function normalizeTrafficReplayEvents(events = []) {
  return (Array.isArray(events) ? events : []).map((event, index) => {
    const timestampMs = dateValue(event?.timestamp);
    const offsetSeconds = Number(event?.offset_seconds);
    const source = event?.src ?? event?.source_address ?? "Unknown source";
    const destination = event?.dst ?? event?.destination_address ?? "Unknown destination";
    const protocol = event?.protocol ?? event?.transport ?? "Unknown";
    const rawLength = Object.hasOwn(event || {}, "sampled_length") ? event.sampled_length : event?.bytes;
    const parsedLength = rawLength === null || rawLength === undefined || rawLength === "" ? null : Number(rawLength);
    const parsedPackets = Number(event?.packets);
    return {
      id: event?.id ?? `${event?.flow_id || "flow"}-${index}`,
      timestamp: event?.timestamp ?? null,
      timestampMs,
      offsetSeconds: Number.isFinite(offsetSeconds) ? offsetSeconds : null,
      source_address: String(source), source_port: event?.sport ?? event?.source_port ?? null,
      destination_address: String(destination), destination_port: event?.dport ?? event?.destination_port ?? null,
      protocol: String(protocol), transport: event?.transport ?? event?.protocol ?? null,
      bytes: Number.isFinite(parsedLength) ? Math.max(0, parsedLength) : null,
      packets: Number.isFinite(parsedPackets) ? Math.max(0, parsedPackets) : 1,
      source_scope: event?.src_scope ?? event?.source_scope ?? "unknown",
      destination_scope: event?.dst_scope ?? event?.destination_scope ?? "unknown",
      flow_id: event?.flow_id ?? "Unavailable",
      sourceLane: getReplayLane(event?.src_scope ?? event?.source_scope),
      destinationLane: getReplayLane(event?.dst_scope ?? event?.destination_scope),
      lane: getReplayLane(event?.dst_scope ?? event?.destination_scope ?? event?.src_scope ?? event?.source_scope),
      _index: index,
    };
  }).sort((a, b) => {
    // Do not compare a capture offset with a wall-clock timestamp: it would invent chronology.
    if (a.timestampMs !== null && b.timestampMs !== null) return a.timestampMs - b.timestampMs || a._index - b._index;
    if (a.timestampMs !== null) return -1;
    if (b.timestampMs !== null) return 1;
    return (a.offsetSeconds ?? Number.POSITIVE_INFINITY) - (b.offsetSeconds ?? Number.POSITIVE_INFINITY) || a._index - b._index;
  });
}

export function filterTrafficReplayEvents(events = [], filters = {}) {
  const ip = String(filters.ip || filters.query || "").trim().toLowerCase();
  const protocol = String(filters.protocol || "").trim().toLowerCase();
  const from = dateValue(filters.from || filters.start);
  const to = dateValue(filters.to || filters.end);
  const hasExactEndpoint = Boolean(ip) && events.some((event) => event.source_address.toLowerCase() === ip || event.destination_address.toLowerCase() === ip);
  return events.filter((event) => {
    const endpointMatch = !ip || (hasExactEndpoint ? event.source_address.toLowerCase() === ip || event.destination_address.toLowerCase() === ip : event.source_address.toLowerCase().includes(ip) || event.destination_address.toLowerCase().includes(ip));
    const protocolMatch = !protocol || protocol === "all" || event.protocol.toLowerCase() === protocol;
    const afterStart = from === null || (event.timestampMs !== null && event.timestampMs >= from);
    const beforeEnd = to === null || (event.timestampMs !== null && event.timestampMs <= to);
    const publicOnly = !filters.excludePrivate || (event.sourceLane !== "internal" && event.destinationLane !== "internal");
    return endpointMatch && protocolMatch && afterStart && beforeEnd && publicOnly;
  });
}

export function getReplayTimelinePosition(event, events = []) {
  return getReplayTimelinePositions(events)[events.indexOf(event)] ?? 50;
}

const getReplayEventTime = (event) => event?.timestampMs ?? (event?.offsetSeconds === null || event?.offsetSeconds === undefined ? null : event.offsetSeconds * 1000);

export function getReplayTimelinePositions(events = []) {
  const hasWallClock = events.some((event) => event.timestampMs !== null);
  const hasOffsetOnly = events.some((event) => event.timestampMs === null && event.offsetSeconds !== null);
  if ((hasWallClock && hasOffsetOnly) || (!hasWallClock && !hasOffsetOnly)) {
    return events.map((_, index) => events.length < 2 ? 50 : (index / (events.length - 1)) * 100);
  }
  const values = events.map(getReplayEventTime).filter(Number.isFinite);
  if (values.length < 2) return events.map(() => 50);
  const earliest = Math.min(...values);
  const latest = Math.max(...values);
  return events.map((event) => {
    const value = getReplayEventTime(event);
    if (!Number.isFinite(value) || latest === earliest) return 50;
    return Math.max(0, Math.min(100, ((value - earliest) / (latest - earliest)) * 100));
  });
}

export function getReplayPlaybackPlan(eventCount, speed = 1) {
  const cadenceMs = 50;
  const targetDurationMs = 18000 / Math.max(0.5, speed);
  const stepSize = Math.max(1, Math.ceil((Math.max(1, eventCount) * cadenceMs) / targetDurationMs));
  return { cadenceMs, stepSize };
}

export function getReplayPlaybackInterval(eventCount, speed = 1) {
  return getReplayPlaybackPlan(eventCount, speed).cadenceMs;
}

export function getTrafficReplayControlState({ visibleEventCount = 0, protocolCount = 0, cursor = 0, playing = false, speed = 1, zoom = 1, grid = true } = {}) {
  const hasVisibleEvents = visibleEventCount > 0;
  return {
    hasVisibleEvents,
    canChangeProtocol: protocolCount > 0,
    canChangeSpeed: hasVisibleEvents,
    canZoomOut: hasVisibleEvents && zoom > 0.75,
    canZoomIn: hasVisibleEvents && zoom < 2,
    canFit: hasVisibleEvents && zoom !== 1,
    canToggleGrid: hasVisibleEvents,
    canRestart: hasVisibleEvents && (cursor !== 0 || playing || speed !== 1 || zoom !== 1 || grid !== true),
  };
}

export function getReplayMarkerIndexes(eventCount, cursor = 0, cap = 240) {
  if (!eventCount) return [];
  const last = eventCount - 1;
  const selected = Math.max(0, Math.min(last, cursor));
  if (eventCount <= cap) return Array.from({ length: eventCount }, (_, index) => index);
  const indexes = new Set([0, selected, last]);
  const slots = Math.max(0, cap - indexes.size);
  for (let step = 1; step <= slots; step += 1) indexes.add(Math.round((step * last) / (slots + 1)));
  return [...indexes].sort((a, b) => a - b);
}


export function summarizeTrafficReplayEvents(replayOrEvents = [], filters = {}) {
  const rawEvents = Array.isArray(replayOrEvents) ? replayOrEvents : replayOrEvents?.events;
  const events = filterTrafficReplayEvents(normalizeTrafficReplayEvents(rawEvents), filters);
  const protocolMap = new Map();
  const endpointMap = new Map();
  const totalBytes = events.reduce((sum, event) => sum + (event.bytes ?? 0), 0);
  const packetCount = events.reduce((sum, event) => sum + event.packets, 0);
  const addEndpoint = (ip, event, direction) => {
    const current = endpointMap.get(ip) || { ip, bytes: 0, packets: 0, flowIds: new Set(), sent_bytes: 0, received_bytes: 0 };
    current.bytes += event.bytes ?? 0;
    current.packets += event.packets;
    current.flowIds.add(event.flow_id);
    if (direction === "sent") current.sent_bytes += event.bytes ?? 0;
    else current.received_bytes += event.bytes ?? 0;
    endpointMap.set(ip, current);
  };
  for (const event of events) {
    const protocol = protocolMap.get(event.protocol) || { name: event.protocol, bytes: 0, packets: 0, flowIds: new Set() };
    protocol.bytes += event.bytes ?? 0;
    protocol.packets += event.packets;
    protocol.flowIds.add(event.flow_id);
    protocolMap.set(event.protocol, protocol);
    addEndpoint(event.source_address, event, "sent");
    addEndpoint(event.destination_address, event, "received");
  }
  const protocol_distribution = [...protocolMap.values()].map((item) => ({ name: item.name, bytes: item.bytes, packets: item.packets, flow_count: item.flowIds.size, percent: totalBytes ? Number(((item.bytes / totalBytes) * 100).toFixed(2)) : 0 })).sort((a, b) => b.bytes - a.bytes || a.name.localeCompare(b.name));
  const endpoint_ranking = [...endpointMap.values()].map(({ flowIds, ...item }) => ({ ...item, flow_count: flowIds.size })).sort((a, b) => b.bytes - a.bytes || a.ip.localeCompare(b.ip));
  return { events, totalBytes, packetCount, flowCount: new Set(events.map((event) => event.flow_id)).size, endpointCount: endpoint_ranking.length, protocol_distribution, endpoint_ranking };
}

export function getTrafficReplayCoverage(replay = {}, eventCount = null) {
  const meta = replay && typeof replay === "object" ? replay : {};
  const numericOrNull = (value) => value === null || value === undefined || value === "" || !Number.isFinite(Number(value)) ? null : Number(value);
  const returned = numericOrNull(meta.returned_event_count) ?? eventCount ?? 0;
  const sampled = numericOrNull(meta.sampled_event_count) ?? returned;
  const representedPackets = numericOrNull(meta.represented_packet_count);
  const totalPackets = numericOrNull(meta.total_packet_count);
  const sampledFlows = numericOrNull(meta.sampled_flow_count);
  const totalFlows = numericOrNull(meta.total_flow_count);
  const packetEvidence = representedPackets !== null || totalPackets !== null ? totalPackets !== null && representedPackets !== null ? `; ${representedPackets.toLocaleString()} of ${totalPackets.toLocaleString()} parsed packets belong to sampled flows` : representedPackets !== null ? `; ${representedPackets.toLocaleString()} parsed packets belong to sampled flows` : `; ${totalPackets.toLocaleString()} parsed packets total` : "";
  const flowEvidence = sampledFlows !== null || totalFlows !== null ? sampledFlows !== null && totalFlows !== null ? `; ${sampledFlows.toLocaleString()} of ${totalFlows.toLocaleString()} flows sampled` : sampledFlows !== null ? `; ${sampledFlows.toLocaleString()} sampled flows` : `; ${totalFlows.toLocaleString()} total flows` : "";
  const filterEvidence = eventCount !== null && eventCount !== returned ? `${eventCount.toLocaleString()} match active filters; ` : "";
  if (meta.truncated) return `${filterEvidence}${returned.toLocaleString()} returned replay events from ${sampled.toLocaleString()} sampled events; results are truncated${packetEvidence}${flowEvidence}`;
  if (String(meta.coverage || "").toLowerCase() === "sampled") return `${filterEvidence}Sampled replay coverage: ${returned.toLocaleString()} returned events from ${sampled.toLocaleString()} sampled events${packetEvidence}${flowEvidence}`;
  if (String(meta.coverage || "").toLowerCase() === "complete") return `${filterEvidence}Complete replay coverage: ${returned.toLocaleString()} replay events${packetEvidence}${flowEvidence.replace(" flows sampled", " flows represented")}`;
  if (String(meta.coverage || "").toLowerCase() === "unavailable") return `${filterEvidence}Replay coverage unavailable; ${returned.toLocaleString()} replay events shown${packetEvidence}${flowEvidence}`;
  if (representedPackets !== null || totalPackets !== null) return `${filterEvidence}${returned.toLocaleString()} replay events shown; ${representedPackets !== null ? `${representedPackets.toLocaleString()}${totalPackets !== null ? ` of ${totalPackets.toLocaleString()}` : ""} parsed packets belong to sampled flows` : `${totalPackets.toLocaleString()} parsed packets total`}`;
  return `${filterEvidence}${returned.toLocaleString()} replay event${returned === 1 ? "" : "s"} shown`;
}

export function formatReplayTime(event) {
  if (event.timestampMs !== null) return new Date(event.timestampMs).toLocaleString();
  if (event.offsetSeconds !== null) return `Capture +${event.offsetSeconds.toFixed(3)} s`;
  return "Time unavailable";
}

export function formatExactReplayTimestamp(event) {
  if (event.timestamp !== null && event.timestamp !== undefined && event.timestampMs !== null) {
    return typeof event.timestamp === "number" || /^\d+(?:\.\d+)?$/.test(String(event.timestamp).trim())
      ? `${new Date(event.timestampMs).toISOString()} (capture timestamp: ${event.timestamp})`
      : String(event.timestamp);
  }
  if (event.offsetSeconds !== null) return `Capture +${event.offsetSeconds.toFixed(3)} s (timestamp unavailable)`;
  return "Timestamp unavailable";
}

export function formatReplayBytes(bytes = 0) {
  if (bytes === null || bytes === undefined) return "Length unavailable";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / 1024 ** 2).toFixed(1)} MiB`;
}
