const PATTERNS = {
  url: /\b(?:https?|wss?):\/\/[^\s<>'"`]+/gi,
  email: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}\b/gi,
  mac: /\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b/gi,
  hostname: /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b/gi,
  ipv4: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
  capture: /\b[^\s/\\]+\.(?:pcap|pcapng)\b/gi,
  path: /(?:\/[A-Za-z0-9._-]+){2,}|\b[A-Z]:\\(?:[^\\\s]+\\)+[^\\\s]*/g,
  uuid: /\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b/gi,
  hash: /\b[0-9a-f]{32,128}\b/gi,
  caseId: /\b(?:case|analysis|job|run)[-_][A-Za-z0-9._:-]+\b/gi,
};

const IPV6_CANDIDATE = /(?<![A-Za-z0-9:])[A-Za-z0-9:.]+(?![A-Za-z0-9:])/g;

function isValidIpv4(value) {
  const pieces = value.split(".");
  return pieces.length === 4 && pieces.every((piece) => /^\d{1,3}$/.test(piece) && Number(piece) <= 255);
}

function isValidIpv6(value) {
  if (!value.includes(":")) return false;
  let candidate = value;
  let ipv4Slots = 0;
  if (candidate.includes(".")) {
    const separator = candidate.lastIndexOf(":");
    if (separator < 0 || !isValidIpv4(candidate.slice(separator + 1))) return false;
    candidate = candidate.slice(0, separator);
    ipv4Slots = 2;
  }
  const compressed = candidate.includes("::");
  if ((candidate.match(/::/g) || []).length > 1) return false;
  const groups = candidate.split(":").filter(Boolean);
  if (!groups.every((group) => /^[0-9A-Fa-f]{1,4}$/.test(group))) return false;
  const slots = groups.length + ipv4Slots;
  return compressed ? slots < 8 : slots === 8;
}

function containsIpv6Suffix(value) {
  if (isValidIpv6(value)) return true;
  for (let index = 1; index < value.length; index += 1) {
    if (isValidIpv6(value.slice(index))) return true;
  }
  return false;
}

const LABELS = {
  url: "URL",
  email: "EMAIL",
  mac: "MAC",
  ipv6: "IP",
  hostname: "HOST",
  ipv4: "IP",
  capture: "CAPTURE",
  path: "PATH",
  uuid: "ID",
  hash: "HASH",
  caseId: "ID",
};

function createTokenRegistry() {
  const registries = new Map();
  return (kind, rawValue) => {
    const normalized = String(rawValue).toLowerCase();
    if (!registries.has(kind)) registries.set(kind, new Map());
    const registry = registries.get(kind);
    if (!registry.has(normalized)) registry.set(normalized, registry.size + 1);
    return `[${kind} ${String(registry.get(normalized)).padStart(2, "0")}]`;
  };
}

function isSecretKey(key) {
  return /(?:^|_)(?:api_?)?key$|password|secret|token/i.test(key);
}

export function sanitizeWorkbenchPayload(payload) {
  const tokenFor = createTokenRegistry();

  const redactString = (value) => {
    let redacted = value.replace(PATTERNS.url, (match) => tokenFor("URL", match));
    redacted = redacted.replace(IPV6_CANDIDATE, (match) => {
      const candidate = match.replace(/[.,;!?]+$/, "");
      const suffix = match.slice(candidate.length);
      return containsIpv6Suffix(candidate) ? `${tokenFor("IP", candidate)}${suffix}` : match;
    });
    for (const [patternName, pattern] of Object.entries(PATTERNS)) {
      if (patternName === "url") continue;
      redacted = redacted.replace(pattern, (match) => tokenFor(LABELS[patternName], match));
    }
    return redacted;
  };

  const visit = (value, path = []) => {
    const key = path.at(-1) || "";

    if (Array.isArray(value)) return value.map((item, index) => visit(item, [...path, String(index)]));
    if (value && typeof value === "object") {
      return Object.fromEntries(Object.entries(value).map(([childKey, childValue]) => [childKey, visit(childValue, [...path, childKey])]));
    }

    if (typeof value === "string") {
      if (isSecretKey(key) && value) return "[SECRET REDACTED]";
      if (/^(?:active_)?(?:case|analysis|job|run)_id$/.test(key) || (path.includes("cases") && key === "id")) return tokenFor("ID", value);
      if (key === "active_case_title" || (path.includes("cases") && key === "title")) return "[CASE TITLE REDACTED]";
      if (path.includes("notes") && key === "content") return "[NOTE REDACTED]";
      if (path.includes("jobs") && key === "name") return tokenFor("CAPTURE", value);
      if (key === "flow_id") return tokenFor("ID", value);
      if (key === "city") return tokenFor("CITY", value);
      if (key === "country") return tokenFor("COUNTRY", value);
      if (/^cfg_home_(?:city|country|continent)$/.test(key)) return "[HOME LOCATION REDACTED]";
      return redactString(value);
    }

    if (typeof value === "number" && /^(?:lat|lon|latitude|longitude|cfg_home_lat|cfg_home_lon)$/.test(key)) return 0;
    return value;
  };

  return visit(payload);
}

export function isPrivacyMode(search = "") {
  return new URLSearchParams(search).get("privacy") === "1";
}
