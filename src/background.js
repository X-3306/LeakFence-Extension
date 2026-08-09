import {
  DECISION,
  canonicalizeOrigin,
  chooseDecision,
  detectBuiltInSecrets,
  extractSecretCandidates,
  isProbablyPassword,
  normalizeOriginList,
  previewSecret,
  redactBuiltInSecrets,
  redactRecord,
  serviceForOrigin
} from "./shared.mjs";

const STORAGE_KEYS = Object.freeze({
  initialized: "cg.initialized",
  masterKey: "cg.masterKey.v1",
  credentials: "cg.credentials.v1",
  settings: "cg.settings.v1",
  audit: "cg.audit.v1"
});

const DEFAULT_SETTINGS = Object.freeze({
  clearOnBlock: true,
  promptRegistration: false,
  allowUserOriginOverrides: false,
  patternGuard: true,
  redactOnBlock: true,
  language: "en",
  minPasswordLength: 6,
  maxAuditEvents: 300
});

let cache = {
  initialized: false,
  masterKeyBytes: null,
  hmacKey: null,
  credentials: [],
  settings: { ...DEFAULT_SETTINGS },
  policy: null,
  audit: []
};

chrome.runtime.onInstalled.addListener(() => {
  void ensureInitialized();
});

chrome.runtime.onStartup.addListener(() => {
  void ensureInitialized();
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  handleMessage(message, sender)
    .then((response) => sendResponse({ ok: true, ...response }))
    .catch((error) => {
      console.error("[LeakFence Local]", error);
      sendResponse({ ok: false, error: error.message || String(error) });
    });
  return true;
});

async function handleMessage(message, sender) {
  await ensureInitialized();
  const type = message?.type;

  switch (type) {
    case "GET_STATE":
      return getPublicState(message?.origin);
    case "CHECK_SECRET":
      return assessSecret(message.secret, message.origin, message.url, "check");
    case "ASSESS_SECRETS":
      return assessSecrets(message.secrets || [], message.origin, message.url, message.source || "submit");
    case "ASSESS_TEXT":
      return assessText(message.text || "", message.origin, message.url, message.source || "text");
    case "REGISTER_SECRET":
      return registerSecret(message);
    case "EXTEND_CREDENTIAL_ORIGIN":
      return extendCredentialOrigin(message.credentialId, message.origin);
    case "DELETE_CREDENTIAL":
      return deleteCredential(message.credentialId);
    case "UPDATE_SETTINGS":
      return updateSettings(message.patch || {});
    case "GET_AUDIT":
      return { audit: cache.audit };
    case "CLEAR_AUDIT":
      cache.audit = [];
      await chrome.storage.local.set({ [STORAGE_KEYS.audit]: cache.audit });
      return { audit: [] };
    case "LOG_OVERRIDE":
      await appendAudit({
        type: "override",
        origin: canonicalizeOrigin(message.origin || sender?.url || "https://invalid.local"),
        decision: message.decision || DECISION.ALLOW,
        details: message.details || "User override."
      });
      return {};
    default:
      throw new Error(`Unknown message type: ${type}`);
  }
}

async function ensureInitialized() {
  if (cache.initialized) {
    return;
  }

  const [stored, builtInPolicy] = await Promise.all([
    chrome.storage.local.get(Object.values(STORAGE_KEYS)),
    loadBuiltInPolicy()
  ]);

  cache.settings = deepMerge(DEFAULT_SETTINGS, stored[STORAGE_KEYS.settings] || {});
  cache.credentials = Array.isArray(stored[STORAGE_KEYS.credentials]) ? stored[STORAGE_KEYS.credentials] : [];
  cache.audit = Array.isArray(stored[STORAGE_KEYS.audit]) ? stored[STORAGE_KEYS.audit] : [];
  cache.policy = builtInPolicy;

  let masterKey = stored[STORAGE_KEYS.masterKey];
  if (!masterKey) {
    const keyBytes = crypto.getRandomValues(new Uint8Array(32));
    masterKey = base64UrlEncode(keyBytes);
    await chrome.storage.local.set({
      [STORAGE_KEYS.initialized]: true,
      [STORAGE_KEYS.masterKey]: masterKey,
      [STORAGE_KEYS.settings]: cache.settings,
      [STORAGE_KEYS.credentials]: cache.credentials,
      [STORAGE_KEYS.audit]: cache.audit
    });
  }

  cache.masterKeyBytes = base64UrlDecode(masterKey);
  cache.hmacKey = await crypto.subtle.importKey(
    "raw",
    cache.masterKeyBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  cache.initialized = true;
}

async function loadBuiltInPolicy() {
  const response = await fetch(chrome.runtime.getURL("data/policy.json"));
  if (!response.ok) {
    throw new Error(`Cannot load built-in policy: HTTP ${response.status}`);
  }
  const policy = await response.json();
  validatePolicy(policy);
  return policy;
}

async function getPublicState(origin) {
  const normalizedOrigin = safeCanonicalizeOrigin(origin);
  return {
    settings: cache.settings,
    policy: {
      schemaVersion: cache.policy.schemaVersion,
      version: cache.policy.version,
      generatedAt: cache.policy.generatedAt,
      expiresAt: cache.policy.expiresAt,
      services: cache.policy.services
    },
    credentials: cache.credentials.filter((record) => record.status !== "deleted").map(redactRecord),
    secrets: cache.credentials.filter((record) => record.status !== "deleted").map(redactRecord),
    credentialCount: cache.credentials.filter((record) => record.status !== "deleted").length,
    secretCount: cache.credentials.filter((record) => record.status !== "deleted").length,
    currentService: normalizedOrigin ? serviceForOrigin(cache.policy, normalizedOrigin) : null
  };
}

async function assessSecrets(secrets, origin, url, source = "submit") {
  const normalizedOrigin = canonicalizeOrigin(origin);
  const results = [];
  for (const secret of secrets) {
    if (isProbablyPassword(secret, cache.settings.minPasswordLength)) {
      results.push(await assessSecret(secret, normalizedOrigin, url, source));
    }
  }

  const patternHits = [];
  for (const secret of secrets) {
    patternHits.push(...detectBuiltInSecrets(secret, normalizedOrigin, cache.settings.patternGuard));
  }
  const patternBlock = makePatternBlock(patternHits, normalizedOrigin);
  if (patternBlock) {
    await appendBlockAudit(patternBlock, normalizedOrigin, url, source);
    return { ...patternBlock, allResults: results };
  }

  const block = results.find((result) => result.decision === DECISION.BLOCK);
  if (block) {
    return { ...block, allResults: results };
  }

  const prompt = results.find((result) => result.decision === DECISION.PROMPT_REGISTER);
  if (prompt) {
    return { ...prompt, allResults: results };
  }

  const allow = results.find((result) => result.decision === DECISION.ALLOW);
  if (allow) {
    return { ...allow, allResults: results };
  }

  return {
    decision: DECISION.UNKNOWN,
    reason: "No submitted secret matched a protected credential.",
    service: serviceForOrigin(cache.policy, normalizedOrigin),
    authorized: [],
    unauthorized: [],
    allResults: results
  };
}

async function assessText(text, origin, url, source = "text") {
  const normalizedOrigin = canonicalizeOrigin(origin);
  const candidates = extractSecretCandidates(text);
  const exact = await assessSecrets(candidates, normalizedOrigin, url, source);
  if (exact.decision === DECISION.BLOCK || exact.decision === DECISION.ALLOW) {
    return {
      ...exact,
      redactedText: exact.decision === DECISION.BLOCK
        ? await redactExactCandidates(redactBuiltInSecrets(text, cache.settings.patternGuard), candidates, normalizedOrigin)
        : text
    };
  }

  const patternHits = detectBuiltInSecrets(text, normalizedOrigin, cache.settings.patternGuard);
  const patternBlock = makePatternBlock(patternHits, normalizedOrigin);
  if (patternBlock) {
    await appendBlockAudit(patternBlock, normalizedOrigin, url, source);
    return {
      ...patternBlock,
      allResults: exact.allResults || [],
      redactedText: redactBuiltInSecrets(text, cache.settings.patternGuard)
    };
  }

  return {
    decision: DECISION.UNKNOWN,
    reason: "No protected secret or enabled pattern matched this text.",
    service: serviceForOrigin(cache.policy, normalizedOrigin),
    authorized: [],
    unauthorized: [],
    allResults: exact.allResults || []
  };
}

async function redactExactCandidates(text, candidates, origin) {
  let output = text;
  for (const candidate of candidates) {
    if (!isProbablyPassword(candidate, cache.settings.minPasswordLength)) {
      continue;
    }
    const tag = await fingerprint(candidate);
    const unauthorized = cache.credentials.some((record) =>
      record.status !== "deleted" &&
      Array.isArray(record.tags) &&
      record.tags.includes(tag) &&
      !normalizeOriginList(record.authorizedOrigins || []).includes(canonicalizeOrigin(origin))
    );
    if (unauthorized && candidate.length >= cache.settings.minPasswordLength) {
      output = output.split(candidate).join("[PROTECTED_SECRET_REDACTED]");
    }
  }
  return output;
}

async function assessSecret(secret, origin, url, source) {
  const normalizedOrigin = canonicalizeOrigin(origin);
  if (!isProbablyPassword(secret, cache.settings.minPasswordLength)) {
    return {
      decision: DECISION.INVALID,
      reason: "The value is outside the configured credential length bounds.",
      authorized: [],
      unauthorized: [],
      service: serviceForOrigin(cache.policy, normalizedOrigin)
    };
  }

  const tag = await fingerprint(secret);
  const matches = cache.credentials.filter((record) =>
    record.status !== "deleted" && Array.isArray(record.tags) && record.tags.includes(tag)
  );
  const decision = chooseDecision({
    matches,
    origin: normalizedOrigin,
    policy: cache.policy,
    settings: cache.settings
  });

  if (decision.decision === DECISION.BLOCK) {
    await appendAudit({
      type: "block",
      origin: normalizedOrigin,
      url,
      source,
      decision: decision.decision,
      credentialIds: decision.unauthorized.map((record) => record.id),
      labels: decision.unauthorized.map((record) => record.label),
      details: decision.reason
    });
  }

  return sanitizeDecision(decision);
}

async function registerSecret(message) {
  const secret = message.secret;
  const origin = safeCanonicalizeOrigin(message.origin) || "https://chatgpt.com";
  if (!isProbablyPassword(secret, cache.settings.minPasswordLength)) {
    throw new Error("Secret is too short to protect.");
  }

  const service = serviceForOrigin(cache.policy, origin);
  const authorizedOrigins = normalizeOriginList(
    message.authorizedOrigins?.length
      ? message.authorizedOrigins
      : []
  );
  const label = sanitizeLabel(message.label || service?.name || new URL(origin).hostname);
  const tag = await fingerprint(secret);
  const now = new Date().toISOString();
  const record = {
    id: crypto.randomUUID(),
    label,
    tags: [tag],
    authorizedOrigins,
    loginUrls: service?.loginUrls || [message.url].filter(Boolean),
    createdAt: now,
    updatedAt: now,
    status: "active"
  };

  cache.credentials.push(record);
  await persistCredentials();
  await appendAudit({
    type: "register",
    origin,
    url: message.url,
    decision: DECISION.ALLOW,
    credentialIds: [record.id],
    labels: [record.label],
    details: "Secret fingerprint registered locally."
  });

  return { credential: redactRecord(record), decision: DECISION.ALLOW };
}

async function extendCredentialOrigin(credentialId, origin) {
  if (!cache.settings.allowUserOriginOverrides) {
    throw new Error("User origin overrides are disabled.");
  }

  const normalizedOrigin = canonicalizeOrigin(origin);
  const record = cache.credentials.find((item) => item.id === credentialId && item.status !== "deleted");
  if (!record) {
    throw new Error("Protected secret not found.");
  }

  record.authorizedOrigins = normalizeOriginList([...(record.authorizedOrigins || []), normalizedOrigin]);
  record.updatedAt = new Date().toISOString();
  await persistCredentials();
  await appendAudit({
    type: "origin_override",
    origin: normalizedOrigin,
    decision: DECISION.ALLOW,
    credentialIds: [record.id],
    labels: [record.label],
    details: "User added a new authorized origin for a protected secret."
  });
  return { credential: redactRecord(record) };
}

async function deleteCredential(credentialId) {
  const record = cache.credentials.find((item) => item.id === credentialId && item.status !== "deleted");
  if (!record) {
    return { deleted: false };
  }
  record.status = "deleted";
  record.updatedAt = new Date().toISOString();
  await persistCredentials();
  await appendAudit({
    type: "delete",
    decision: DECISION.ALLOW,
    credentialIds: [record.id],
    labels: [record.label],
    details: "Protected secret record deleted by the user."
  });
  return { deleted: true };
}

async function updateSettings(patch) {
  cache.settings = deepMerge(cache.settings, patch);
  await chrome.storage.local.set({ [STORAGE_KEYS.settings]: cache.settings });
  return { settings: cache.settings };
}

async function fingerprint(secret) {
  const bytes = new TextEncoder().encode(`leakfence-local:v1\0${secret}`);
  const signature = await crypto.subtle.sign("HMAC", cache.hmacKey, bytes);
  return base64UrlEncode(new Uint8Array(signature));
}

function makePatternBlock(patternHits, origin) {
  const unauthorized = (patternHits || []).filter((hit) => !hit.allowedHere);
  if (unauthorized.length === 0) {
    return null;
  }
  return {
    decision: DECISION.BLOCK,
    reason: "Sensitive data pattern detected outside an allowed origin.",
    service: serviceForOrigin(cache.policy, origin),
    authorized: [],
    unauthorized: unauthorized.map((hit) => ({
      id: hit.id,
      label: hit.label,
      type: hit.type,
      severity: hit.severity,
      matchPreview: hit.matchPreview,
      authorizedOrigins: hit.authorizedOrigins,
      status: "active"
    })),
    suggestedRedactions: unauthorized.map((hit) => ({
      label: hit.label,
      preview: hit.matchPreview,
      replacement: `[${hit.label.toUpperCase().replace(/[^A-Z0-9]+/g, "_")}_REDACTED]`
    }))
  };
}

async function appendBlockAudit(decision, origin, url, source) {
  await appendAudit({
    type: "block",
    origin,
    url,
    source,
    decision: decision.decision,
    credentialIds: decision.unauthorized.map((record) => record.id),
    labels: decision.unauthorized.map((record) => `${record.label} ${record.matchPreview ? `(${record.matchPreview})` : ""}`.trim()),
    details: decision.reason
  });
}

async function persistCredentials() {
  await chrome.storage.local.set({ [STORAGE_KEYS.credentials]: cache.credentials });
}

async function appendAudit(event) {
  cache.audit.unshift({
    at: new Date().toISOString(),
    ...event
  });
  cache.audit = cache.audit.slice(0, cache.settings.maxAuditEvents);
  await chrome.storage.local.set({ [STORAGE_KEYS.audit]: cache.audit });
}

function sanitizeDecision(decision) {
  return {
    decision: decision.decision,
    reason: decision.reason,
    service: decision.service,
    authorized: decision.authorized.map(sanitizeRecordLike),
    unauthorized: decision.unauthorized.map(sanitizeRecordLike),
    suggestedRedactions: decision.suggestedRedactions || []
  };
}

function sanitizeRecordLike(record) {
  if (record.type === "pattern") {
    return {
      id: record.id,
      label: record.label,
      type: record.type,
      severity: record.severity,
      matchPreview: record.matchPreview || previewSecret(record.label),
      authorizedOrigins: normalizeOriginList(record.authorizedOrigins || []),
      status: record.status || "active"
    };
  }
  return redactRecord(record);
}

function validatePolicy(policy) {
  if (!policy || policy.schemaVersion !== 1 || !Array.isArray(policy.services)) {
    throw new Error("Invalid policy schema.");
  }
  for (const service of policy.services) {
    normalizeOriginList(service.authorizedOrigins || []);
  }
}

function sanitizeLabel(value) {
  return String(value || "Protected secret").replace(/\s+/g, " ").trim().slice(0, 80) || "Protected secret";
}

function safeCanonicalizeOrigin(origin) {
  if (!origin) {
    return null;
  }
  try {
    return canonicalizeOrigin(origin);
  } catch {
    return null;
  }
}

function deepMerge(base, patch) {
  const output = Array.isArray(base) ? [...base] : { ...base };
  for (const [key, value] of Object.entries(patch || {})) {
    if (value && typeof value === "object" && !Array.isArray(value) && base?.[key] && typeof base[key] === "object") {
      output[key] = deepMerge(base[key], value);
    } else {
      output[key] = value;
    }
  }
  return output;
}

function base64UrlEncode(bytes) {
  const binary = Array.from(bytes, (byte) => String.fromCharCode(byte)).join("");
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function base64UrlDecode(value) {
  const padded = `${value}${"=".repeat((4 - (value.length % 4)) % 4)}`;
  const binary = atob(padded.replace(/-/g, "+").replace(/_/g, "/"));
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}
