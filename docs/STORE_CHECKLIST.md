# Store Checklist

## Chrome Web Store

- Manifest V3 only.
- No remotely hosted code.
- No CDN scripts.
- No eval/new Function.
- Explain host permissions: content scripts are limited to supported AI chat
  origins because the product only prevents accidental AI prompt leaks.
- Privacy policy must state that secret fingerprints remain local and no
  telemetry, prompt text, audit data, or usage analytics are sent.
- Public listing copy should mention that the project is open source and link
  to https://github.com/X-3306/LeakFence-Extension for verification.
- Provide screenshots of popup, options page, local guide, and block prompt.
- For local/manual testing, use the extension folder directly with
  `Load unpacked`.

## Edge Add-ons

The same MV3 package should be a close port. Test popup, options, storage,
content scripts, and main-world script behavior in Edge before submission.

## Firefox

Treat as a port, not a direct upload promise. Verify:

- MV3 background behavior,
- support for static content script `world: "MAIN"`,
- host permission prompts,
- service worker lifetime,
- `browser_specific_settings`.

## Safari

Treat as a separate port via Safari Web Extension tooling.

## Review Evidence

Before public release, keep evidence for:

- unit tests,
- manual browser test matrix,
- policy review process,
- threat model and limitations,
- dependency inventory,
- reproducible package hash.
