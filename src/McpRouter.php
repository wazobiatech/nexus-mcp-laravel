<?php

namespace Wazobia\NexusMcp;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

/**
 * Registers the three standard Nexus MCP endpoints on a Laravel router.
 *
 *   GET  /health          — K8s liveness probe (no HMAC)
 *   GET  /mcp/manifest    — Returns manifest JSON (HMAC-protected)
 *   POST /mcp/call        — Invoke a named tool (HMAC-protected)
 *
 * Usage in routes/api.php or a dedicated mcp.php route file:
 *
 *   McpRouter::register(
 *       manifest: $manifest,
 *       tools:    $tools,
 *       secret:   env('MCP_HMAC_SECRET'),
 *   );
 *
 * By default routes are prefixed with nothing (root level), but you can
 * pass a prefix:
 *
 *   McpRouter::register($manifest, $tools, $secret, prefix: 'api');
 */
class McpRouter
{
    /**
     * Register health, manifest, and tool-call routes.
     *
     * @param Manifest            $manifest  Service manifest
     * @param McpToolDefinition[] $tools     Tool definitions with handlers
     * @param string              $secret    HMAC secret (from MCP_HMAC_SECRET env var)
     * @param string              $prefix    Optional route prefix (default: empty)
     */
    public static function register(
        Manifest $manifest,
        array $tools,
        string $secret,
        string $prefix = '',
    ): void {
        $trimmedPrefix = trim($prefix, '/');

        // Health endpoint — OUTSIDE HMAC group (kubelet probes have no signature)
        $healthPath = $trimmedPrefix ? "/{$trimmedPrefix}/health" : '/health';
        Route::get($healthPath, function (): JsonResponse {
            return response()->json(['status' => 'ok']);
        });

        // HMAC-protected routes
        $middlewareSecret = HmacMiddleware::class . ':' . $secret;

        Route::middleware($middlewareSecret)
            ->prefix($trimmedPrefix)
            ->group(function () use ($manifest, $tools): void {

                // GET /mcp/manifest
                Route::get('/mcp/manifest', function () use ($manifest): JsonResponse {
                    return response()->json($manifest->toArray());
                });

                // POST /mcp/call
                Route::post('/mcp/call', function (Request $request) use ($tools): JsonResponse {
                    $body      = $request->json()->all();
                    $toolName  = $body['tool'] ?? null;
                    $arguments = $body['arguments'] ?? [];

                    if (! $toolName) {
                        return response()->json(['error' => 'missing tool name'], 400);
                    }

                    $definition = null;
                    foreach ($tools as $t) {
                        if ($t->name === $toolName) {
                            $definition = $t;
                            break;
                        }
                    }

                    if ($definition === null) {
                        return response()->json(['error' => "tool not found: {$toolName}"], 404);
                    }

                    if (! is_callable($definition->handler)) {
                        return response()->json(
                            ['error' => "tool has no handler: {$toolName}"],
                            501,
                        );
                    }

                    try {
                        $result = ($definition->handler)($arguments, [
                            'headers' => $request->headers->all(),
                            'method'  => $request->method(),
                            'path'    => $request->getPathInfo(),
                        ]);

                        return response()->json(['result' => $result]);
                    } catch (\Throwable $e) {
                        return response()->json(['error' => $e->getMessage()], 400);
                    }
                });
            });
    }
}
