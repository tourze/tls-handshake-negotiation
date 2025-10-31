<?php

declare(strict_types=1);

namespace Tourze\TLSHandshakeNegotiation\Tests\Session;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshakeNegotiation\Session\TLS13PSKSession;

/**
 * @internal
 */
#[CoversClass(TLS13PSKSession::class)]
final class TLS13PSKSessionTest extends TestCase
{
    public function testConstructorDefault(): void
    {
        $session = new TLS13PSKSession();

        $this->assertSame('', $session->getSessionId());
        $this->assertSame('', $session->getPskIdentity());
    }

    public function testConstructorWithParameters(): void
    {
        $sessionId = 'test_session_123';
        $pskIdentity = 'test_psk_identity';

        $session = new TLS13PSKSession($sessionId, $pskIdentity);

        $this->assertSame($sessionId, $session->getSessionId());
        $this->assertSame($pskIdentity, $session->getPskIdentity());
    }

    public function testGetSetPskIdentity(): void
    {
        $session = new TLS13PSKSession();
        $pskIdentity = 'new_psk_identity';

        $session->setPskIdentity($pskIdentity);

        $this->assertSame($pskIdentity, $session->getPskIdentity());
    }

    public function testSetterMethods(): void
    {
        $session = new TLS13PSKSession();
        $pskIdentity = 'fluent_psk_identity';

        $session->setPskIdentity($pskIdentity);

        $this->assertSame($pskIdentity, $session->getPskIdentity());
    }
}
