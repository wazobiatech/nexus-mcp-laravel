<?php

namespace Wazobia\NexusMcp;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Laravel HTTP middleware that validates incoming HMAC-SHA256 signatures.
 *
 * Exempt paths (/health, /health/live, /health/ready) are passed through
 * without a signature so Kubernetes liveness/readiness probes work.
 *
 * Usage via McpRouter::register() (recommended — secret bound via container):
 *
 *   McpRouter::register(manifest: $manifest, tools: $tools, secret: env('MCP_HMAC_SECRET'));
 *
 * Direct usage (secret via container binding):
 *
 *   app()->singleton('nexus-mcp.hmac_secret', fn () => env('MCP_HMAC_SECRET'));
 *   Route::middleware(\Wazobia\NexusMcp\HmacMiddleware::class)->group(function () { ... });
 *
 * NOTE: Do NOT pass the secret as a middleware string parameter
 * (Route::middleware(HmacMiddleware::class . ':' . $secret)).
 * Laravel's param parser splits on commas, so any secret containing a comma
 * would be silently truncated. The container binding avoids this entirely.
 */
class HmacMiddleware
{
    /**
     * Paths exempt from HMAC — kubelet probes don't send signed requests.
     *
     * @var string[]
     */
    protected array $unprotected = [
        '/health',
        '/health/live',
        '/health/ready',
        '/api/health',
        '/api/health/live',
        '/api/health/ready',
    ];

    /**
     * Handle an incoming request.
     *
     * The HMAC secret is resolved from the service container key 'nexus-mcp.hmac_secret'
     * (bound by McpRouter::register). The optional $secret parameter is kept for
     * backward compatibility but the container binding takes precedence.
     *
     * @param Request $request
     * @param Closure(Request): Response $next
     * @param string  $secret  Fallback secret (not recommended — see class docblock)
     */
    public function handle(Request $request, Closure $next, string $secret = ''): Response
    {
        // Prefer container binding over the string param to avoid comma-truncation.
        $secret = app()->bound('nexus-mcp.hmac_secret')
            ? (string) app('nexus-mcp.hmac_secret')
            : $secret;

        // Skip HMAC for health/probe paths
        if (in_array($request->getPathInfo(), $this->unprotected, true)) {
            return $next($request);
        }

        if (empty($secret)) {
            return response()->json(
                ['error' => 'server_misconfiguration', 'reason' => 'MCP_HMAC_SECRET not set'],
                500,
            );
        }

        $sig = $request->header(Hmac::HEADER_SIGNATURE);
        $ts  = $request->header(Hmac::HEADER_TIMESTAMP);

        if (! $sig || ! $ts) {
            return response()->json(
                ['error' => 'unauthorized', 'reason' => 'missing headers'],
                401,
            );
        }

        $timestamp = filter_var($ts, FILTER_VALIDATE_INT);
        if ($timestamp === false || $timestamp <= 0) {
            return response()->json(
                ['error' => 'unauthorized', 'reason' => 'invalid timestamp'],
                401,
            );
        }

        if (Hmac::isStale($timestamp)) {
            return response()->json(
                ['error' => 'unauthorized', 'reason' => 'stale timestamp'],
                401,
            );
        }

        // Build full path including query string (must match client signing)
        $path = $request->getPathInfo();
        if ($qs = $request->getQueryString()) {
            $path .= '?' . $qs;
        }

        $expected = Hmac::computeSignature($request->getMethod(), $path, $ts, $secret);

        // hash_equals() is timing-safe — prevents timing attacks
        if (! hash_equals($expected, $sig)) {
            return response()->json(
                ['error' => 'unauthorized', 'reason' => 'signature mismatch'],
                401,
            );
        }

        return $next($request);
    }
}
