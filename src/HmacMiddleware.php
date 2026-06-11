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
 * Usage in routes/api.php:
 *
 *   Route::middleware(\Wazobia\NexusMcp\HmacMiddleware::class . ':' . env('MCP_HMAC_SECRET'))
 *       ->group(function () {
 *           Route::get('/mcp/manifest', ...);
 *           Route::post('/mcp/call', ...);
 *       });
 *
 * Or register an alias in app/Http/Kernel.php:
 *
 *   'hmac' => \Wazobia\NexusMcp\HmacMiddleware::class
 *
 * Then use: Route::middleware('hmac:' . env('MCP_HMAC_SECRET'))
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
     * @param Request $request
     * @param Closure(Request): Response $next
     * @param string  $secret  Passed as middleware parameter: 'hmac:secret'
     */
    public function handle(Request $request, Closure $next, string $secret = ''): Response
    {
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
