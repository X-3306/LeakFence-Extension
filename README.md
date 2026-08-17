![LeakFence](/assets/banner1.png)

# LeakFence Local

Manifest V3 browser extension for local-first AI prompt leak prevention.

LeakFence Local protects against a specific, common mistake: pasting secrets into
AI chats. It runs only on supported AI chat surfaces, pauses paste/submit
actions, checks text locally, and blocks detected secrets before the prompt is
sent.

There is NO account, NO developer server, NO telemetry, and NO upload of
passwords, hashes, fingerprints, prompts, or audit events.

The project is open source so this privacy claim can be checked directly in the
code: https://github.com/X-3306/LeakFence-Extension

## Core Invariant

> Protected secrets and high-risk secret patterns should not be pasted or sent
> into supported AI chat surfaces.

## Implemented

- Manifest V3 extension for Chrome/Edge.
- Content scripts restricted to supported AI chat origins instead of `<all_urls>`.
- Local HMAC-SHA-256 fingerprints for manually protected exact secrets.
- Per-install random HMAC key in `chrome.storage.local`.
- Synchronous paste blocking: paste is paused, checked locally, then inserted
  only if allowed.
- Redacted paste option for detected pattern leaks.
- Submit/click interception for forms and common prompt send actions.
- Monitoring for `input`, `textarea`, and `contenteditable` prompt boxes.
- Pattern Guard for OpenAI keys, GitHub tokens, AWS keys, Google API keys,
  Stripe keys, Slack tokens, JWTs, private key blocks, recovery phrase contexts,
  IBAN, and PESEL.
- Best-effort main-world lock for `fetch`, XHR, `sendBeacon`, `WebSocket`,
  `form.submit()`, and `form.requestSubmit()` after a risky secret is found.
- Options UI with local language selection, GitHub link, audit log, guide, and
  supported AI chat coverage.

## Supported AI Surfaces

The current bundled list includes ChatGPT, Claude, Gemini, Copilot/Bing Chat,
Perplexity, Poe, DeepSeek Chat, Mistral Le Chat, Meta AI, Grok, HuggingChat,
You.com AI, Blackbox AI, Qwen Chat, and Canva AI.

## Not Guaranteed

- It does not inspect arbitrary websites.
- It does not protect against malware, keyloggers, malicious extensions, or a
  compromised browser profile.
- It cannot inspect every possible browser/runtime exfiltration path.
- Pattern detection is conservative and may miss unusual formats.

## Install
https://chromewebstore.google.com/detail/ebfbbbljfmppofkkealknbaihfoajioi?utm_source=item-share-cb

