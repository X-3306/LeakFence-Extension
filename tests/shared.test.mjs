import test from "node:test";
import assert from "node:assert/strict";
import {
  DECISION,
  canonicalizeOrigin,
  chooseDecision,
  detectBuiltInSecrets,
  extractSecretCandidates,
  isOriginAuthorized,
  normalizeOriginList,
  redactBuiltInSecrets
} from "../src/shared.mjs";

test("canonicalizeOrigin normalizes default ports and host case", () => {
  assert.equal(canonicalizeOrigin("HTTPS://Example.COM:443/login"), "https://example.com");
  assert.equal(canonicalizeOrigin("http://Example.COM:80/login"), "http://example.com");
  assert.equal(canonicalizeOrigin("https://example.com:8443/login"), "https://example.com:8443");
});

test("normalizeOriginList de-duplicates and sorts origins", () => {
  assert.deepEqual(normalizeOriginList(["https://b.test", "https://A.test", "https://a.test/"]), [
    "https://a.test",
    "https://b.test"
  ]);
});

test("isOriginAuthorized uses exact canonical origins", () => {
  const record = { authorizedOrigins: ["https://accounts.example.com"] };
  assert.equal(isOriginAuthorized(record, "https://accounts.example.com/login"), true);
  assert.equal(isOriginAuthorized(record, "https://evil.example.com/login"), false);
});

test("chooseDecision blocks when any matching credential is unauthorized", () => {
  const matches = [
    { id: "1", status: "active", authorizedOrigins: ["https://a.test"] },
    { id: "2", status: "active", authorizedOrigins: ["https://b.test"] }
  ];
  const result = chooseDecision({ matches, origin: "https://a.test", policy: { services: [] }, settings: {} });
  assert.equal(result.decision, DECISION.BLOCK);
  assert.equal(result.authorized.length, 1);
  assert.equal(result.unauthorized.length, 1);
});

test("chooseDecision prompts registration on known origin", () => {
  const policy = {
    services: [
      { id: "svc", name: "Service", authorizedOrigins: ["https://login.example.com"] }
    ]
  };
  const result = chooseDecision({
    matches: [],
    origin: "https://login.example.com",
    policy,
    settings: { promptRegistration: true }
  });
  assert.equal(result.decision, DECISION.PROMPT_REGISTER);
});

test("detectBuiltInSecrets finds known API-key patterns locally", () => {
  const text = "Please review sk-proj-abcdefghijklmnopqrstuvwxyz1234567890 before deploy.";
  const hits = detectBuiltInSecrets(text, "https://chatgpt.com", true);
  assert.equal(hits.some((hit) => hit.label === "OpenAI API key" && hit.allowedHere === false), true);
});

test("detectBuiltInSecrets honors allowed origins for patterns", () => {
  const text = "Token: ghp_abcdefghijklmnopqrstuvwxyzABCDE1234567890";
  const hits = detectBuiltInSecrets(text, "https://github.com", true);
  assert.equal(hits.some((hit) => hit.label === "GitHub token" && hit.allowedHere === true), true);
});

test("extractSecretCandidates includes whole text and token chunks", () => {
  const candidates = extractSecretCandidates("prefix abcdefghijklmnopqrstuvwxyz suffix");
  assert.equal(candidates.includes("prefix abcdefghijklmnopqrstuvwxyz suffix"), true);
  assert.equal(candidates.includes("abcdefghijklmnopqrstuvwxyz"), true);
});

test("redactBuiltInSecrets redacts realistic token-shaped samples", () => {
  const text = [
    "sk-proj-abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
    "ghp_abcdefghijklmnopqrstuvwxyzABCDE1234567890",
    "AKIAIOSFODNN7EXAMPLE",
    `AIza${"A".repeat(35)}`,
    "sk_test_abcdefghijklmnopqrstuvwxyz123456",
    "xoxb-123456789012-123456789012-abcdefghijklmnopqrstuvwxyz",
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
  ].join("\n");

  const redacted = redactBuiltInSecrets(text, true);
  assert.match(redacted, /\[OPENAI_API_KEY_REDACTED]/);
  assert.match(redacted, /\[GITHUB_TOKEN_REDACTED]/);
  assert.match(redacted, /\[AWS_ACCESS_KEY_ID_REDACTED]/);
  assert.match(redacted, /\[GOOGLE_API_KEY_REDACTED]/);
  assert.match(redacted, /\[STRIPE_SECRET_KEY_REDACTED]/);
  assert.match(redacted, /\[SLACK_TOKEN_REDACTED]/);
  assert.match(redacted, /\[JWT_REDACTED]/);
});

test("fake placeholder tokens that do not match real formats are not over-detected", () => {
  const text = [
    "ghp_TEST_ONLY_NOT_VALID_000000",
    "AKIA_TEST_ONLY_INVALID_0000",
    "AIzaTEST_ONLY_INVALID_000000",
    "sk_test_NOT_A_REAL_STRIPE_KEY_000",
    "eyJTEST_INVALID_TOKEN_PAYLOAD_SIGNATURE",
    "-----BEGIN PRIVATE KEY----- TEST-ONLY-NOT-A-REAL-PRIVATE-KEY -----END PRIVATE KEY-----"
  ].join("\n");

  assert.deepEqual(detectBuiltInSecrets(text, "https://chatgpt.com", true), []);
});
