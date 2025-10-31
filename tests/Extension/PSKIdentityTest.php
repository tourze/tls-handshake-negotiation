<?php

declare(strict_types=1);

namespace Tourze\TLSHandshakeNegotiation\Extension;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
#[CoversClass(PSKIdentity::class)]
final class PSKIdentityTest extends TestCase
{
    public function testGetSetIdentity(): void
    {
        $pskIdentity = new PSKIdentity();
        $identity = 'test_psk_identity_string';

        $pskIdentity->setIdentity($identity);

        $this->assertSame($identity, $pskIdentity->getIdentity());
    }

    public function testGetSetObfuscatedTicketAge(): void
    {
        $pskIdentity = new PSKIdentity();
        $age = 3600000; // 1 hour in milliseconds

        $pskIdentity->setObfuscatedTicketAge($age);

        $this->assertSame($age, $pskIdentity->getObfuscatedTicketAge());
    }

    public function testDefaultValues(): void
    {
        $pskIdentity = new PSKIdentity();

        $this->assertSame('', $pskIdentity->getIdentity());
        $this->assertSame(0, $pskIdentity->getObfuscatedTicketAge());
    }

    public function testSetterMethods(): void
    {
        $pskIdentity = new PSKIdentity();

        $pskIdentity->setIdentity('test_identity');
        $this->assertSame('test_identity', $pskIdentity->getIdentity());

        $pskIdentity->setObfuscatedTicketAge(1234567);
        $this->assertSame(1234567, $pskIdentity->getObfuscatedTicketAge());
    }
}
