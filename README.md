# wazobia/nexus-mcp-laravel

Laravel HMAC middleware and MCP server helpers for the [Nexus MCP](https://github.com/wazobiatech/nexus-mcp-contract) ecosystem.

The PHP/Laravel equivalent of the TypeScript (`@wazobiatech/nexus-mcp`), Python (`wazobiatech-nexus-mcp`), and Go (`github.com/wazobiatech/nexus-mcp-go`) SDKs. All four SDKs produce byte-identical HMAC-SHA256 signatures, verified by the shared [contract test vectors](https://github.com/wazobiatech/nexus-mcp-contract).

---

## Requirements

- PHP `^8.1`
- Laravel `^10.0` or `^11.0`
- Guzzle `^7.0`

---

## Installation

```bash
composer require wazobia/nexus-mcp-laravel
```

The `McpServiceProvider` is auto-discovered — no manual registration needed.

---

## Quick Start

Create a route file `routes/mcp.php` and register it in your `RouteServiceProvider` (or `bootstrap/app.php` in Laravel 11):

```php
use Wazobia\NexusMcp\Manifest;
use Wazobia\NexusMcp\ManifestContext;
use Wazobia\NexusMcp\McpRouter;
use Wazobia\NexusMcp\McpToolDefinition;

$manifest = new Manifest(
    namespace: 'my-service',
    description: 'My service MCP manifest',
    version: '1.0.0',
    context: new ManifestContext(
        boundedContext: 'my-service',
        description: 'Handles ...',
        capabilities: ['...'],
        knownGaps: [],
    ),
    tools: [],
);

$tools = [
    new McpToolDefinition(
        name: 'my_tool',
        description: 'Does something useful',
        inputSchema: [
            'type' => 'object',
            'properties' => [
                'message' => ['type' => 'string', 'description' => 'Input message'],
            ],
            'required' => ['message'],
        ],
        handler: function (array $args): array {
            return ['result' => 'Hello, ' . $args['message']];
        },
    ),
];

McpRouter::register(
    manifest: $manifest,
    tools:    $tools,
    secret:   env('MCP_HMAC_SECRET'),
    healthExtra: [
        'server'    => 'my-service-mcp-server',
        'version'   => '1.0.0',
        'timestamp' => now()->toISOString(),
    ],
);
```

This registers three routes:

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/health` | None | K8s liveness probe |
| `GET` | `/mcp/manifest` | HMAC | Returns service manifest JSON |
| `POST` | `/mcp/call` | HMAC | Invokes a named tool |

---

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `MCP_HMAC_SECRET` | ✅ | Shared HMAC-SHA256 secret (min 16 chars) |

---

## Classes

### `Hmac`

Core signing utilities.

```php
use Wazobia\NexusMcp\Hmac;

// Compute a signature
$sig = Hmac::computeSignature('POST', '/mcp/call', '1718000000', $secret);

// Sign a request — returns [signature, timestamp]
[$sig, $ts] = Hmac::signRequest('GET', '/mcp/manifest', $secret);

// Check if a timestamp is stale (> 300s from now)
$stale = Hmac::isStale(1718000000);
```

### `HmacMiddleware`

Laravel HTTP middleware that validates incoming HMAC signatures on MCP routes. Automatically exempts `/health`, `/health/live`, and `/health/ready` for K8s probes.

```php
// Recommended — via McpRouter::register() (secret bound through container)
McpRouter::register($manifest, $tools, env('MCP_HMAC_SECRET'));

// Direct usage
app()->singleton('nexus-mcp.hmac_secret', fn () => env('MCP_HMAC_SECRET'));
Route::middleware(\Wazobia\NexusMcp\HmacMiddleware::class)->group(function () {
    // your HMAC-protected routes
});
```

> **Note:** Do not pass the secret as a middleware string parameter (`HmacMiddleware::class . ':' . $secret`). Laravel's param parser splits on commas, which would silently truncate any secret containing one. The container binding avoids this entirely.

### `HmacClient`

Guzzle-based HTTP client that automatically signs every outbound request.

```php
use Wazobia\NexusMcp\HmacClient;

$client = new HmacClient('http://mercury:4001', env('MERCURY_HMAC_SECRET'));

// GET /mcp/manifest
$response = $client->get('/mcp/manifest');
$manifest = json_decode($response->getBody(), true);

// POST /mcp/call
$response = $client->post('/mcp/call', [
    'json' => ['tool' => 'login', 'arguments' => ['email' => 'a@b.com']],
]);

// Query strings are signed correctly (ksorted, RFC3986-encoded)
$response = $client->get('/mcp/manifest', ['query' => ['version' => '1', 'format' => 'full']]);
```

### `McpRouter`

Registers the three standard MCP endpoints on the Laravel router.

```php
McpRouter::register(
    manifest:    $manifest,       // Manifest DTO
    tools:       $tools,          // McpToolDefinition[]
    secret:      $secret,         // HMAC secret
    prefix:      'api',           // Optional route prefix (default: empty)
    healthExtra: [                // Optional extra fields in /health response
        'server'    => 'my-service',
        'version'   => '1.0.0',
        'timestamp' => now()->toISOString(),
        'endpoints' => ['POST /mcp/call' => 'Tool invocation'],
    ],
);
```

### `McpToolDefinition`

DTO for a tool definition. The `handler` is excluded from manifest JSON serialisation.

```php
use Wazobia\NexusMcp\McpToolDefinition;

$tool = new McpToolDefinition(
    name:        'create_post',
    description: 'Create a new blog post',
    inputSchema: [
        'type'       => 'object',
        'properties' => [
            'title'   => ['type' => 'string'],
            'content' => ['type' => 'string'],
        ],
        'required' => ['title', 'content'],
    ],
    handler: function (array $args, array $context): array {
        // $args    — tool arguments from the MCP call
        // $context — ['headers' => [...], 'method' => 'POST', 'path' => '/mcp/call']
        return ['id' => '123', 'title' => $args['title']];
    },
);
```

### `Manifest` / `ManifestContext`

DTOs that serialise to the Nexus MCP manifest schema.

```php
use Wazobia\NexusMcp\Manifest;
use Wazobia\NexusMcp\ManifestContext;

$manifest = new Manifest(
    namespace:   'my-service',
    description: 'My service tools',
    version:     '1.0.0',
    context: new ManifestContext(
        boundedContext: 'my-service',
        description:    'Handles blog management',
        capabilities:   ['create posts', 'manage tags'],
        knownGaps:      ['no draft support yet'],
    ),
    tools: $tools, // McpToolDefinition[] — handlers stripped automatically
);
```

---

## HMAC Contract

All Nexus MCP SDKs use the same signing spec:

```
payload = METHOD.upper() + path + timestamp
          where path includes query string, no fragment, no host
          timestamp = Unix epoch, whole seconds, decimal string
digest  = HMAC-SHA256(secret_utf8, payload_utf8), lowercase hex
headers = x-signature: {digest}
          x-timestamp: {timestamp}
reject if |now - timestamp| > 300
```

Cross-language correctness is verified by [16 contract test vectors](https://github.com/wazobiatech/nexus-mcp-contract/blob/v1.0.0/vectors.json) shared across all four SDKs.

---

## Testing

```bash
composer install
./vendor/bin/phpunit
```

- `tests/Unit/HmacTest.php` — 8 unit tests (signature format, method normalisation, staleness window)
- `tests/Contract/VectorTest.php` — 16 cross-language contract vectors (vendored, hermetic — no network required)

---

## License

MIT
