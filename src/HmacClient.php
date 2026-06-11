<?php

namespace Wazobia\NexusMcp;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use Psr\Http\Message\ResponseInterface;

/**
 * Guzzle-based HTTP client that automatically signs every request with HMAC-SHA256.
 *
 * The signature covers the full path **including query string**, matching the
 * server-side HmacMiddleware which signs `path + "?" + queryString`.
 *
 * Usage:
 *
 *   $client = new HmacClient('http://mercury:4001', env('MERCURY_HMAC_SECRET'));
 *   $response = $client->get('/mcp/manifest');
 *   $manifest = json_decode($response->getBody(), true);
 *
 *   $response = $client->post('/mcp/call', [
 *       'json' => ['tool' => 'login', 'arguments' => ['email' => 'a@b.com', ...]],
 *   ]);
 */
class HmacClient
{
    private Client $client;

    private string $secret;

    /**
     * @param string $baseUrl     Base URL for all requests e.g. http://mercury:4001
     * @param string $secret      Shared HMAC-SHA256 secret
     * @param array  $guzzleConfig Extra Guzzle client options (timeouts, SSL, etc.)
     */
    public function __construct(string $baseUrl, string $secret, array $guzzleConfig = [])
    {
        $this->secret = $secret;
        $this->client = new Client(array_merge(
            ['base_uri' => rtrim($baseUrl, '/'), 'timeout' => 30.0],
            $guzzleConfig,
        ));
    }

    /**
     * Build HMAC auth headers for a given method + path.
     *
     * @return array{x-signature: string, x-timestamp: string}
     */
    private function authHeaders(string $method, string $path): array
    {
        [$sig, $ts] = Hmac::signRequest($method, $path, $this->secret);

        return [
            Hmac::HEADER_SIGNATURE => $sig,
            Hmac::HEADER_TIMESTAMP => $ts,
        ];
    }

    /**
     * Build a full signed path, merging query params into the path string.
     *
     * Guzzle appends `query` option after this call, but we must encode them
     * here too so the signature covers the same string the server will verify.
     */
    private function signedPath(string $path, array $query = []): string
    {
        if (empty($query)) {
            return $path;
        }

        return $path . '?' . http_build_query($query);
    }

    /**
     * Send a signed GET request.
     *
     * @param string $path    Request path (e.g. /mcp/manifest)
     * @param array  $options Guzzle request options (query, headers, etc.)
     * @throws GuzzleException
     */
    public function get(string $path, array $options = []): ResponseInterface
    {
        $query  = is_array($options['query'] ?? null) ? $options['query'] : [];
        $signed = $this->signedPath($path, $query);

        $options['headers'] = array_merge(
            $options['headers'] ?? [],
            $this->authHeaders('GET', $signed),
        );

        return $this->client->get($path, $options);
    }

    /**
     * Send a signed POST request.
     *
     * @param string $path    Request path (e.g. /mcp/call)
     * @param array  $options Guzzle request options (json, body, query, headers, etc.)
     * @throws GuzzleException
     */
    public function post(string $path, array $options = []): ResponseInterface
    {
        $query  = is_array($options['query'] ?? null) ? $options['query'] : [];
        $signed = $this->signedPath($path, $query);

        $options['headers'] = array_merge(
            $options['headers'] ?? [],
            $this->authHeaders('POST', $signed),
        );

        return $this->client->post($path, $options);
    }
}
