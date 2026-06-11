# nexus-mcp-laravel — Handoff

## Status
🔵 In Progress — library built, wired into Muse locally, not yet published to Packagist.

## What This Is
Laravel Composer package providing HMAC-SHA256 middleware and MCP server helpers
for the Nexus MCP ecosystem. PHP equivalent of:
- `@wazobiatech/nexus-mcp` (TypeScript)
- `wazobiatech-nexus-mcp` (Python)
- `github.com/wazobiatech/nexus-mcp-go` (Go)

## Key Exports

| Class | Purpose |
|---|---|
| `Wazobia\NexusMcp\Hmac` | `computeSignature()`, `signRequest()`, `isStale()` |
| `Wazobia\NexusMcp\HmacMiddleware` | Laravel middleware — validates incoming HMAC on MCP routes |
| `Wazobia\NexusMcp\HmacClient` | Guzzle client — signs outbound requests to other MCP services |
| `Wazobia\NexusMcp\McpRouter` | `McpRouter::register()` — wires `/health`, `/mcp/manifest`, `/mcp/call` |
| `Wazobia\NexusMcp\McpToolDefinition` | Tool definition DTO (handler excluded from manifest) |
| `Wazobia\NexusMcp\Manifest` | Manifest DTO (serialized at `/mcp/manifest`) |
| `Wazobia\NexusMcp\ManifestContext` | DDD context metadata embedded in manifest |
| `Wazobia\NexusMcp\McpServiceProvider` | Auto-discovered provider — registers `hmac` middleware alias |

## HMAC Contract
```
payload = METHOD.upper() + path + timestamp
digest  = HMAC-SHA256(secret_utf8, payload_utf8), lowercase hex
headers = x-signature, x-timestamp (Unix seconds)
reject if |now - timestamp| > 300
```
Path includes query string, no fragment, no host — identical to all other SDKs.

## Tests
- `tests/Unit/HmacTest.php` — 8 unit tests
- `tests/Contract/VectorTest.php` — fetches 16 vectors from public GitHub mirror, verifies byte-identical signatures across all SDK languages

## Publishing
Not yet on Packagist. Currently consumed by Muse via a local `path` repository in `composer.json`.

To publish:
1. Push to `github.com/wazobiatech/nexus-mcp-laravel` (public)
2. Register on packagist.org with the GitHub repo
3. Tag `v1.0.0`
4. Remove the `path` repository from Muse's `composer.json` and use `"wazobia/nexus-mcp-laravel": "^1.0"`

## Open Questions
- Packagist vs private Composer registry (same decision as TS → npmjs.org restricted)
- Laravel 11 support tested? (composer.json supports `^10|^11` but only tested on 10 via Muse)
