<?php

namespace Wazobia\NexusMcp;

/**
 * HMAC-SHA256 signing helpers — canonical Nexus MCP contract.
 *
 * Payload: METHOD.upper() + path + timestamp
 * Digest:  HMAC-SHA256(secret_utf8, payload_utf8), lowercase hex
 * Window:  |now - timestamp| <= 300 seconds
 *
 * Identical contract implemented in:
 *   - @wazobiatech/nexus-mcp        (TypeScript)
 *   - wazobiatech-nexus-mcp         (Python)
 *   - github.com/wazobiatech/nexus-mcp-go  (Go)
 */
class Hmac
{
    public const MAX_AGE_SECONDS = 300;
    public const HEADER_SIGNATURE = 'x-signature';
    public const HEADER_TIMESTAMP = 'x-timestamp';

    /**
     * Compute HMAC-SHA256 signature for a request.
     *
     * @param string $method    HTTP method (any case — uppercased internally)
     * @param string $path      Full path including query string, no fragment, no host
     * @param string $timestamp Unix epoch as a decimal string
     * @param string $secret    Shared symmetric key
     * @return string           Lowercase hex digest
     */
    public static function computeSignature(
        string $method,
        string $path,
        string $timestamp,
        string $secret,
    ): string {
        $payload = strtoupper($method) . $path . $timestamp;

        return hash_hmac('sha256', $payload, $secret);
    }

    /**
     * Sign a request and return [signature, timestamp].
     *
     * @param string   $method     HTTP method
     * @param string   $path       Full path including query string
     * @param string   $secret     Shared symmetric key
     * @param int|null $timestamp  Override Unix timestamp (for deterministic tests)
     * @return array{0: string, 1: string}  [hex signature, unix timestamp string]
     */
    public static function signRequest(
        string $method,
        string $path,
        string $secret,
        ?int $timestamp = null,
    ): array {
        $ts = $timestamp ?? time();
        $tsStr = (string) $ts;

        return [self::computeSignature($method, $path, $tsStr, $secret), $tsStr];
    }

    /**
     * Check whether a timestamp is outside the 300-second validity window.
     */
    public static function isStale(int $timestamp): bool
    {
        return abs(time() - $timestamp) > self::MAX_AGE_SECONDS;
    }
}
