import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { canonicalizeOrigin } from "../src/shared.mjs";

test("built-in policy is valid and uses canonical origins", async () => {
  const policy = JSON.parse(await readFile(new URL("../data/policy.json", import.meta.url), "utf8"));
  assert.equal(policy.schemaVersion, 1);
  assert.ok(Number.isInteger(policy.version));
  assert.ok(policy.services.length >= 10);
  assert.ok(policy.services.some((service) => service.id === "chatgpt"));
  assert.ok(policy.services.some((service) => service.id === "claude"));
  assert.ok(policy.services.some((service) => service.id === "gemini"));

  const ids = new Set();
  for (const service of policy.services) {
    assert.ok(service.id, "service id is required");
    assert.ok(service.name, `service name is required for ${service.id}`);
    assert.equal(ids.has(service.id), false, `duplicate service id: ${service.id}`);
    ids.add(service.id);
    assert.ok(Array.isArray(service.authorizedOrigins), `${service.id} must have origins`);
    assert.ok(service.authorizedOrigins.length > 0, `${service.id} must have at least one origin`);
    for (const origin of service.authorizedOrigins) {
      assert.equal(canonicalizeOrigin(origin), origin, `${service.id} has non-canonical origin ${origin}`);
    }
  }
});
