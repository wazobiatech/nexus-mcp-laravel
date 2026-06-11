<?php

namespace Wazobia\NexusMcp\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Wazobia\NexusMcp\Hmac;

class HmacTest extends TestCase
{
    // Known-good values for sanity (not the contract vectors — those are in VectorTest)
    private const METHOD    = 'GET';
    private const PATH      = '/mcp/manifest';
    private const TIMESTAMP = '1700000000';
    private const SECRET    = 'test-secret';

    public function testComputeSignatureIsLowercaseHex(): void
    {
        $sig = Hmac::computeSignature(self::METHOD, self::PATH, self::TIMESTAMP, self::SECRET);
        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $sig);
    }

    public function testMethodIsUppercasedBeforeSigning(): void
    {
        $upper = Hmac::computeSignature('GET',  self::PATH, self::TIMESTAMP, self::SECRET);
        $lower = Hmac::computeSignature('get',  self::PATH, self::TIMESTAMP, self::SECRET);
        $mixed = Hmac::computeSignature('Get',  self::PATH, self::TIMESTAMP, self::SECRET);

        $this->assertSame($upper, $lower);
        $this->assertSame($upper, $mixed);
    }

    public function testSignRequestReturnsTwoElementArray(): void
    {
        [$sig, $ts] = Hmac::signRequest('POST', '/mcp/call', self::SECRET);

        $this->assertMatchesRegularExpression('/^[0-9a-f]{64}$/', $sig);
        $this->assertMatchesRegularExpression('/^\d+$/', $ts);
    }

    public function testSignRequestTimestampOverride(): void
    {
        [$sig1, $ts1] = Hmac::signRequest('GET', '/mcp/manifest', self::SECRET, 1700000000);
        [$sig2, $ts2] = Hmac::signRequest('GET', '/mcp/manifest', self::SECRET, 1700000000);

        $this->assertSame('1700000000', $ts1);
        $this->assertSame($sig1, $sig2);
    }

    public function testIsStaleReturnsFalseForFreshTimestamp(): void
    {
        $this->assertFalse(Hmac::isStale(time()));
        $this->assertFalse(Hmac::isStale(time() - 299));
        $this->assertFalse(Hmac::isStale(time() + 299));
    }

    public function testIsStaleReturnsTrueForExpiredTimestamp(): void
    {
        $this->assertTrue(Hmac::isStale(time() - 301));
        $this->assertTrue(Hmac::isStale(time() + 301));
        $this->assertTrue(Hmac::isStale(0));
    }

    public function testDifferentPathsProduceDifferentSignatures(): void
    {
        $a = Hmac::computeSignature('GET', '/mcp/manifest',           self::TIMESTAMP, self::SECRET);
        $b = Hmac::computeSignature('GET', '/mcp/manifest?foo=bar',   self::TIMESTAMP, self::SECRET);
        $c = Hmac::computeSignature('GET', '/mcp/other',              self::TIMESTAMP, self::SECRET);

        $this->assertNotSame($a, $b);
        $this->assertNotSame($a, $c);
    }

    public function testDifferentSecretsProduceDifferentSignatures(): void
    {
        $a = Hmac::computeSignature('GET', self::PATH, self::TIMESTAMP, 'secret-a');
        $b = Hmac::computeSignature('GET', self::PATH, self::TIMESTAMP, 'secret-b');

        $this->assertNotSame($a, $b);
    }
}
