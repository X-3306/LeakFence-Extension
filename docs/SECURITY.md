# Security Model

## Product Definition

LeakFence Local is a local-first AI prompt leak prevention extension. It is not a
general browser DLP tool.

## Security Invariant

On supported AI chat origins, LeakFence should block paste, submit, or prompt
send actions when the text contains a locally protected exact secret or an
enabled high-risk secret pattern.

## Trusted Computing Base

- Extension package contents.
- Chrome extension runtime.
- `chrome.storage.local` integrity and availability.
- Browser WebCrypto implementation.
- Content script and background service worker.

The main-world script is not trusted with secrets. It only receives lock/unlock
signals from the isolated content script after a risky secret is found.

## Fingerprint Design

The extension generates a random per-install 256-bit HMAC key and stores it in
`chrome.storage.local`. A protected exact secret tag is:

```text
HMAC-SHA-256(key, "leakfence-local:v1\0" || secret)
```

Plaintext secrets are never intentionally stored. If both the local database and
HMAC key are stolen, low-entropy secrets can still be guessed offline.

## Controlled Paths

LeakFence attempts to control:

- paste into monitored AI prompt fields,
- text input/change/blur observation,
- form submit events in capture phase,
- common prompt send buttons,
- explicit `form.submit()` and `requestSubmit()` after lock,
- `fetch`, XHR, `navigator.sendBeacon`, and `WebSocket` after lock.

The paste path is synchronous: the extension prevents default paste first, checks
locally, and inserts the text only if allowed.

## Out Of Scope

- Non-AI websites.
- Malware/keyloggers.
- Compromised browser profile.
- Malicious or compromised extension update.
- Another extension with sufficient privileges.
- Closed Shadow DOM internals.
- Full browser-engine-level exfiltration prevention.

## Privacy

- No prompt text is sent to the developer.
- No plaintext secrets are intentionally stored.
- Fingerprints, settings, and audit events stay in `chrome.storage.local`.
- There is no developer server in the MVP.
- There is no telemetry, analytics endpoint, account system, or remote scanning
  endpoint.
- The code is public at https://github.com/X-3306/LeakFence-Extension so these
  claims can be independently verified.
