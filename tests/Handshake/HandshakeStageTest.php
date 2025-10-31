<?php

namespace Tourze\TLSHandshakeNegotiation\Tests\Handshake;

use PHPUnit\Framework\Attributes\CoversClass;
use Tourze\PHPUnitEnum\AbstractEnumTestCase;
use Tourze\TLSHandshakeNegotiation\Handshake\HandshakeStage;

/**
 * 握手阶段枚举测试类
 *
 * @internal
 */
#[CoversClass(HandshakeStage::class)]
final class HandshakeStageTest extends AbstractEnumTestCase
{
    /**
     * 测试HandshakeStage枚举值是否正确
     */
    public function testHandshakeStageValues(): void
    {
        $this->assertSame(1, HandshakeStage::INITIAL->value, 'INITIAL阶段值应为1');
        $this->assertSame(2, HandshakeStage::NEGOTIATING->value, 'NEGOTIATING阶段值应为2');
        $this->assertSame(3, HandshakeStage::KEY_EXCHANGE->value, 'KEY_EXCHANGE阶段值应为3');
        $this->assertSame(4, HandshakeStage::AUTHENTICATION->value, 'AUTHENTICATION阶段值应为4');
        $this->assertSame(5, HandshakeStage::FINISHED->value, 'FINISHED阶段值应为5');
    }

    /**
     * 测试HandshakeStage枚举的顺序性
     */
    public function testHandshakeStageOrder(): void
    {
        $this->assertGreaterThan(HandshakeStage::INITIAL->value, HandshakeStage::NEGOTIATING->value, 'NEGOTIATING应在INITIAL之后');
        $this->assertGreaterThan(HandshakeStage::NEGOTIATING->value, HandshakeStage::KEY_EXCHANGE->value, 'KEY_EXCHANGE应在NEGOTIATING之后');
        $this->assertGreaterThan(HandshakeStage::KEY_EXCHANGE->value, HandshakeStage::AUTHENTICATION->value, 'AUTHENTICATION应在KEY_EXCHANGE之后');
        $this->assertGreaterThan(HandshakeStage::AUTHENTICATION->value, HandshakeStage::FINISHED->value, 'FINISHED应在AUTHENTICATION之后');
    }

    /**
     * 测试toArray方法
     */
    public function testToArray(): void
    {
        $initialArray = HandshakeStage::INITIAL->toArray();
        $this->assertSame(1, $initialArray['value'], 'INITIAL的value应为1');
        $this->assertSame('INITIAL', $initialArray['label'], 'INITIAL的label应为INITIAL');

        $negotiatingArray = HandshakeStage::NEGOTIATING->toArray();
        $this->assertSame(2, $negotiatingArray['value'], 'NEGOTIATING的value应为2');
        $this->assertSame('NEGOTIATING', $negotiatingArray['label'], 'NEGOTIATING的label应为NEGOTIATING');

        $keyExchangeArray = HandshakeStage::KEY_EXCHANGE->toArray();
        $this->assertSame(3, $keyExchangeArray['value'], 'KEY_EXCHANGE的value应为3');
        $this->assertSame('KEY_EXCHANGE', $keyExchangeArray['label'], 'KEY_EXCHANGE的label应为KEY_EXCHANGE');

        $authenticationArray = HandshakeStage::AUTHENTICATION->toArray();
        $this->assertSame(4, $authenticationArray['value'], 'AUTHENTICATION的value应为4');
        $this->assertSame('AUTHENTICATION', $authenticationArray['label'], 'AUTHENTICATION的label应为AUTHENTICATION');

        $finishedArray = HandshakeStage::FINISHED->toArray();
        $this->assertSame(5, $finishedArray['value'], 'FINISHED的value应为5');
        $this->assertSame('FINISHED', $finishedArray['label'], 'FINISHED的label应为FINISHED');
    }

    /**
     * 测试toSelectItem方法
     */
}
