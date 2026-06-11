<?php

namespace Wazobia\NexusMcp\Tests\Contract;

use PHPUnit\Framework\TestCase;
use Wazobia\NexusMcp\Hmac;

/**
 * Contract vector tests — verifies this PHP implementation produces
 * byte-identical signatures to the TypeScript, Python, and Go SDKs.
 *
 * Vectors are fetched from the public GitHub mirror of nexus-mcp-contract
 * (no auth, no git clone needed):
 *
 *   https://raw.githubusercontent.com/wazobiatech/nexus-mcp-contract/v1.0.0/vectors.json
 *
 * The vectors.json file is intentionally NOT committed here — it is always
 * fetched fresh to stay in sync with the canonical contract.
 */
class VectorTest extends TestCase
{
    private const VECTORS_URL =
        'https://raw.githubusercontent.com/wazobiatech/nexus-mcp-contract/v1.0.0/vectors.json';

    private array $vectors;

    protected function setUp(): void
    {
        $this->vectors = $this->loadVectors();
    }

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
                $v['method'],
                $v['path'],
                $v['timestamp'],
                $v['secret'],
                $v['expected_signature'],
                $v['description'] ?? 'unnamed',
            ],
            $vectors,
        );
    }

    private function loadVectors(): array
    {
        $json = @file_get_contents(self::VECTORS_URL);

        if ($json === false) {
            $this->fail(
                "Could not fetch vectors.json from:\n  " . self::VECTORS_URL .
                "\nCheck your internet connection or the public GitHub mirror.",
            );
        }

        $parsed = json_decode($json, true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            $this->fail('vectors.json is not valid JSON: ' . json_last_error_msg());
        }

        $vectors = $parsed['vectors'] ?? null;

        if (! is_array($vectors) || count($vectors) === 0) {
            $this->fail(
                "vectors.json has no 'vectors' array or it is empty. " .
                "Raw response:\n" . substr($json, 0, 200),
            );
        }

        return $vectors;
    }
}
