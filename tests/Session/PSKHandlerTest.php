<?php

declare(strict_types=1);

namespace Tourze\TLSHandshakeNegotiation\Tests\Session;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshakeNegotiation\Session\PSKHandler;
use Tourze\TLSHandshakeNegotiation\Session\TLS13PSKSession;

/**
 * @internal
 */
#[CoversClass(PSKHandler::class)]
final class PSKHandlerTest extends TestCase
{
    private PSKHandler $handler;

    protected function setUp(): void
    {
        parent::setUp();

        $this->handler = new PSKHandler();
    }

    public function testRegisterPSK(): void
    {
        $identity = 'test_identity';
        $psk = 'test_psk_value';

        $this->handler->registerPSK($identity, $psk);

        $retrievedPSK = $this->handler->getPSK($identity);
        $this->assertSame($psk, $retrievedPSK);
    }

    public function testGetPSKReturnsNullForUnknownIdentity(): void
    {
        $psk = $this->handler->getPSK('unknown_identity');
        $this->assertNull($psk);
    }

    public function testRemovePSK(): void
    {
        $identity = 'test_identity';
        $psk = 'test_psk_value';

        $this->handler->registerPSK($identity, $psk);
        $this->assertNotNull($this->handler->getPSK($identity));

        $this->handler->removePSK($identity);
        $this->assertNull($this->handler->getPSK($identity));
    }

    public function testHasPSK(): void
    {
        $identity = 'test_identity';

        $this->assertFalse($this->handler->hasPSK($identity));

        $this->handler->registerPSK($identity, 'psk_value');
        $this->assertTrue($this->handler->hasPSK($identity));
    }

    public function testMultiplePSKRegistration(): void
    {
        $this->handler->registerPSK('id1', 'psk1');
        $this->handler->registerPSK('id2', 'psk2');
        $this->handler->registerPSK('id3', 'psk3');

        $this->assertTrue($this->handler->hasPSK('id1'));
        $this->assertTrue($this->handler->hasPSK('id2'));
        $this->assertTrue($this->handler->hasPSK('id3'));
        $this->assertSame('psk1', $this->handler->getPSK('id1'));
        $this->assertSame('psk2', $this->handler->getPSK('id2'));
        $this->assertSame('psk3', $this->handler->getPSK('id3'));
    }

    public function testSessionBinding(): void
    {
        $identity = 'test_identity';
        $this->handler->registerPSK($identity, 'psk_value');

        $session = new TLS13PSKSession();
        $result = $this->handler->bindSessionToPSK($identity, $session);

        $this->assertTrue($result);
        $this->assertSame($session, $this->handler->getSessionByPSK($identity));
    }

    public function testBindSessionToPSK(): void
    {
        $identity = 'test_identity';
        $session = new TLS13PSKSession();

        // 测试绑定不存在的PSK失败
        $result = $this->handler->bindSessionToPSK($identity, $session);
        $this->assertFalse($result);
        $this->assertNull($this->handler->getSessionByPSK($identity));

        // 注册PSK后绑定成功
        $this->handler->registerPSK($identity, 'psk_value');
        $result = $this->handler->bindSessionToPSK($identity, $session);
        $this->assertTrue($result);
        $this->assertSame($session, $this->handler->getSessionByPSK($identity));

        // 测试绑定新会话会覆盖旧会话
        $newSession = new TLS13PSKSession();
        $result = $this->handler->bindSessionToPSK($identity, $newSession);
        $this->assertTrue($result);
        $this->assertSame($newSession, $this->handler->getSessionByPSK($identity));
        $this->assertNotSame($session, $this->handler->getSessionByPSK($identity));
    }

    public function testRemovePSKClearsSessionBinding(): void
    {
        $identity = 'test_identity';
        $this->handler->registerPSK($identity, 'psk_value');

        $session = new TLS13PSKSession();
        $this->handler->bindSessionToPSK($identity, $session);
        $this->assertSame($session, $this->handler->getSessionByPSK($identity));

        // 移除PSK应该同时清除会话绑定
        $this->assertTrue($this->handler->removePSK($identity));
        $this->assertNull($this->handler->getSessionByPSK($identity));
    }
}
