const PATTERNS = {
  url: /\b(?:https?|wss?):\/\/[^\s<>'"`]+/gi,
  email: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,63}\b/gi,
  mac: /\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b/gi,
  ipv6: /\b(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{1,4}\b/gi,
  hostname: /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b/gi,
  ipv4: /\b(?:\d{1,3}\.){3}\d{1,3}\b/g,
  capture: /\b[^\s/\\]+\.(?:pcap|pcapng)\b/gi,
  path: /(?:\/[A-Za-z0-9._-]+){2,}|\b[A-Z]:\\(?:[^\\\s]+\\)+[^\\\s]*/g,
  uuid: /\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b/gi,
  hash: /\b[0-9a-f]{32,128}\b/gi,
  caseId: /\b(?:case|analysis|job|run)[-_][A-Za-z0-9._:-]+\b/gi,
};

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
    let redacted = value;
    for (const [patternName, pattern] of Object.entries(PATTERNS)) {
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
