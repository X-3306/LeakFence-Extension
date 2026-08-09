export const DECISION = Object.freeze({
  ALLOW: "ALLOW",
  BLOCK: "BLOCK",
  UNKNOWN: "UNKNOWN",
  PROMPT_REGISTER: "PROMPT_REGISTER",
  INVALID: "INVALID",
  STALE: "STALE"
});

export const BUILT_IN_SECRET_PATTERNS = Object.freeze([
  {
    id: "openai-api-key",
    label: "OpenAI API key",
    severity: "high",
    allowedOrigins: ["https://platform.openai.com"],
    regex: /\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b/g
  },
  {
    id: "github-token",
    label: "GitHub token",
    severity: "high",
    allowedOrigins: ["https://github.com"],
    regex: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{30,}\b/g
  },
  {
    id: "aws-access-key",
    label: "AWS access key ID",
    severity: "high",
    allowedOrigins: ["https://console.aws.amazon.com", "https://signin.aws.amazon.com"],
    regex: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g
  },
  {
    id: "google-api-key",
    label: "Google API key",
    severity: "high",
    allowedOrigins: ["https://console.cloud.google.com"],
    regex: /\bAIza[0-9A-Za-z_-]{35}\b/g
  },
  {
    id: "stripe-secret-key",
    label: "Stripe secret key",
    severity: "high",
    allowedOrigins: ["https://dashboard.stripe.com"],
    regex: /\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{20,}\b/g
  },
  {
    id: "slack-token",
    label: "Slack token",
    severity: "high",
    allowedOrigins: ["https://slack.com", "https://api.slack.com"],
    regex: /\bxox[abprs]-[A-Za-z0-9-]{20,}\b/g
  },
  {
    id: "jwt",
    label: "JWT",
    severity: "medium",
    allowedOrigins: [],
    regex: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g
  },
  {
    id: "private-key",
    label: "Private key block",
    severity: "critical",
    allowedOrigins: [],
    regex: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]{40,}?-----END [A-Z ]*PRIVATE KEY-----/g
  },
  {
    id: "crypto-seed-phrase",
    label: "Possible wallet seed phrase",
    severity: "critical",
    allowedOrigins: [],
    regex: /\b(?:seed phrase|recovery phrase|mnemonic)[:\s-]+(?:[a-z]{3,10}\s+){11,23}[a-z]{3,10}\b/gi
  },
  {
    id: "iban",
    label: "IBAN",
    severity: "medium",
    allowedOrigins: [],
    regex: /\b[A-Z]{2}\d{2}(?:\s?[A-Z0-9]){11,30}\b/g
  },
  {
    id: "pesel",
    label: "PESEL",
    severity: "medium",
    allowedOrigins: [],
    regex: /\b\d{11}\b/g
  }
]);

export function canonicalizeOrigin(input) {
  if (!input || typeof input !== "string") {
    throw new TypeError("Origin input must be a non-empty string.");
  }

  const url = input.includes("://") ? new URL(input) : new URL(`https://${input}`);
  const protocol = url.protocol.toLowerCase();
  if (protocol !== "https:" && protocol !== "http:") {
    throw new TypeError(`Unsupported protocol: ${protocol}`);
  }

  const host = url.hostname.toLowerCase();
  const port = url.port && !isDefaultPort(protocol, url.port) ? `:${url.port}` : "";
  return `${protocol}//${host}${port}`;
}

export function isDefaultPort(protocol, port) {
  return (protocol === "https:" && port === "443") || (protocol === "http:" && port === "80");
}

export function normalizeOriginList(origins) {
  return [...new Set((origins || []).map(canonicalizeOrigin))].sort();
}

export function isOriginAuthorized(record, origin) {
  const normalized = canonicalizeOrigin(origin);
  return normalizeOriginList(record.authorizedOrigins || []).includes(normalized);
}

export function serviceForOrigin(policy, origin) {
  const normalized = canonicalizeOrigin(origin);
  return (policy?.services || []).find((service) =>
    normalizeOriginList(service.authorizedOrigins || []).includes(normalized)
  ) || null;
}

export function chooseDecision({ matches, origin, policy, settings }) {
  const activeMatches = (matches || []).filter((record) => record.status !== "deleted");
  if (activeMatches.length === 0) {
    const service = serviceForOrigin(policy, origin);
    if (service && settings?.promptRegistration !== false) {
      return {
        decision: DECISION.PROMPT_REGISTER,
        service,
        authorized: [],
        unauthorized: [],
        reason: "Known login origin with an unregistered credential."
      };
    }

    return {
      decision: DECISION.UNKNOWN,
      service,
      authorized: [],
      unauthorized: [],
      reason: "No protected credential matched this value."
    };
  }

  const authorized = activeMatches.filter((record) => isOriginAuthorized(record, origin));
  const unauthorized = activeMatches.filter((record) => !isOriginAuthorized(record, origin));

  if (unauthorized.length > 0) {
    return {
      decision: DECISION.BLOCK,
      service: serviceForOrigin(policy, origin),
      authorized,
      unauthorized,
      reason: "A protected credential was used outside its authorized origins."
    };
  }

  return {
    decision: DECISION.ALLOW,
    service: serviceForOrigin(policy, origin),
    authorized,
    unauthorized,
    reason: "Every matching protected credential is authorized for this origin."
  };
}

export function isPatternOriginAllowed(pattern, origin) {
  const allowed = normalizeOriginList(pattern.allowedOrigins || []);
  return allowed.length > 0 && allowed.includes(canonicalizeOrigin(origin));
}

export function detectBuiltInSecrets(text, origin, enabled = true) {
  if (!enabled || typeof text !== "string" || text.length < 8) {
    return [];
  }

  const normalizedOrigin = canonicalizeOrigin(origin);
  const hits = [];
  for (const pattern of BUILT_IN_SECRET_PATTERNS) {
    const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
    const matches = [...text.matchAll(regex)].slice(0, 5);
    for (const match of matches) {
      const value = match[0] || "";
      if (!looksLikeUsefulPatternHit(pattern.id, value)) {
        continue;
      }
      hits.push({
        id: `pattern:${pattern.id}`,
        label: pattern.label,
        type: "pattern",
        severity: pattern.severity,
        matchPreview: previewSecret(value),
        authorizedOrigins: normalizeOriginList(pattern.allowedOrigins || []),
        allowedHere: isPatternOriginAllowed(pattern, normalizedOrigin),
        status: "active"
      });
    }
  }
  return dedupePatternHits(hits);
}

export function redactBuiltInSecrets(text, enabled = true) {
  if (!enabled || typeof text !== "string" || text.length < 8) {
    return text;
  }

  let output = text;
  for (const pattern of BUILT_IN_SECRET_PATTERNS) {
    const regex = new RegExp(pattern.regex.source, pattern.regex.flags);
    output = output.replace(regex, (value) => {
      if (!looksLikeUsefulPatternHit(pattern.id, value)) {
        return value;
      }
      return `[${pattern.label.toUpperCase().replace(/[^A-Z0-9]+/g, "_")}_REDACTED]`;
    });
  }
  return output;
}

export function extractSecretCandidates(text) {
  if (typeof text !== "string") {
    return [];
  }
  const candidates = new Set();
  const trimmed = text.trim();
  if (trimmed.length >= 6 && trimmed.length <= 1024) {
    candidates.add(trimmed);
  }

  const tokenRegex = /[A-Za-z0-9_./+=:@$!?#%-]{6,512}/g;
  for (const match of trimmed.matchAll(tokenRegex)) {
    candidates.add(match[0]);
  }

  for (const line of trimmed.split(/\r?\n/)) {
    const value = line.trim();
    if (value.length >= 6 && value.length <= 1024) {
      candidates.add(value);
    }
  }

  return [...candidates].slice(0, 300);
}

export function redactRecord(record) {
  return {
    id: record.id,
    label: record.label,
    authorizedOrigins: normalizeOriginList(record.authorizedOrigins || []),
    loginUrls: record.loginUrls || [],
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
    status: record.status || "active"
  };
}

export function isProbablyPassword(value, minLength = 6) {
  return typeof value === "string" && value.length >= minLength && value.length <= 1024;
}

export function previewSecret(value) {
  if (!value) {
    return "";
  }
  const compact = String(value).replace(/\s+/g, " ").trim();
  if (compact.length <= 14) {
    return "[redacted]";
  }
  return `${compact.slice(0, 4)}...${compact.slice(-4)}`;
}

function dedupePatternHits(hits) {
  const seen = new Set();
  return hits.filter((hit) => {
    const key = `${hit.id}:${hit.matchPreview}`;
    if (seen.has(key)) {
      return false;
    }
    seen.add(key);
    return true;
  });
}

function looksLikeUsefulPatternHit(id, value) {
  if (id === "pesel") {
    return isLikelyPesel(value);
  }
  if (id === "crypto-seed-phrase") {
    return value.trim().split(/\s+/).length >= 12;
  }
  if (id === "iban") {
    return value.replace(/\s+/g, "").length >= 15;
  }
  return true;
}

function isLikelyPesel(value) {
  if (!/^\d{11}$/.test(value)) {
    return false;
  }
  const weights = [1, 3, 7, 9, 1, 3, 7, 9, 1, 3];
  const digits = value.split("").map(Number);
  const sum = weights.reduce((total, weight, index) => total + weight * digits[index], 0);
  return (10 - (sum % 10)) % 10 === digits[10];
}
