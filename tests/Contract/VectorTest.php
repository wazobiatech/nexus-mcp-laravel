<?php

namespace Wazobia\NexusMcp\Tests\Contract;

use PHPUnit\Framework\TestCase;
use Wazobia\NexusMcp\Hmac;

/**
 * Contract vector tests — verifies this PHP implementation produces
 * byte-identical signatures to the TypeScript, Python, and Go SDKs.
 *
 * vectors.json is vendored in tests/Contract/ (pinned to nexus-mcp-contract v1.0.0).
 * To update: replace tests/Contract/vectors.json with the new file and update
 * VECTORS_VERSION below. The network fallback is intentionally removed — hermetic
 * CI is more valuable than always-fetching-fresh (which was also pinned to v1.0.0
 * anyway, so "fresh" was a false promise).
 */
class VectorTest extends TestCase
{
    private const VECTORS_FILE = __DIR__ . '/vectors.json';

    /**
     * @dataProvider vectorProvider
     */
    public function testSignatureMatchesVector(
        string $method,
        string $path,
        string $timestamp,
        string $secret,
        string $expectedSignature,
        string $description,
    ): void {
        $actual = Hmac::computeSignature($method, $path, $timestamp, $secret);

        $this->assertSame(
            $expectedSignature,
            $actual,
            "Vector '{$description}' failed: expected {$expectedSignature}, got {$actual}",
        );
    }

    public function vectorProvider(): array
    {
        $vectors = $this->loadVectors();

        return array_map(
            fn (array $v) => [
                $v['input']['method'],
                $v['input']['path'],
                $v['input']['timestamp'],
                $v['input']['secret'],
                $v['expected']['x-signature'],
                $v['description'] ?? 'unnamed',
            ],
            $vectors,
        );
    }

    private function loadVectors(): array
    {
        if (! file_exists(self::VECTORS_FILE)) {
            $this->fail(
                "Vendored vectors.json not found at:\n  " . self::VECTORS_FILE .
                "\nCopy tests/Contract/vectors.json from nexus-mcp-contract v1.0.0.",
            );
        }

        $json = file_get_contents(self::VECTORS_FILE);

        if ($json === false) {
            $this->fail('Could not read ' . self::VECTORS_FILE);
        }

        $parsed = json_decode($json, true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            $this->fail('vectors.json is not valid JSON: ' . json_last_error_msg());
        }

        $vectors = $parsed['vectors'] ?? null;

        if (! is_array($vectors) || count($vectors) === 0) {
            $this->fail(
                "vectors.json has no 'vectors' array or it is empty.\n" .
                "Raw content:\n" . substr((string) $json, 0, 200),
            );
        }

        return $vectors;
    }
}
