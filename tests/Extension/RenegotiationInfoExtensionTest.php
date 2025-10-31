<?php

namespace Tourze\TLSHandshakeNegotiation\Tests\Extension;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshakeNegotiation\Extension\ExtensionType;
use Tourze\TLSHandshakeNegotiation\Extension\RenegotiationInfoExtension;

/**
 * 安全重协商扩展测试类
 *
 * @internal
 */
#[CoversClass(RenegotiationInfoExtension::class)]
final class RenegotiationInfoExtensionTest extends TestCase
{
    /**
     * 测试创建基本的扩展对象
     */
    public function testBasicExtensionCreation(): void
    {
        $extension = new RenegotiationInfoExtension();
        $this->assertEquals(ExtensionType::RENEGOTIATION_INFO, $extension->getType());
        $this->assertEmpty($extension->getRenegotiatedConnection());
    }

    /**
     * 测试设置和获取重协商连接数据
     */
    public function testSetAndGetRenegotiatedConnection(): void
    {
        $renegotiatedConnection = random_bytes(24);
        $extension = new RenegotiationInfoExtension();
        $extension->setRenegotiatedConnection($renegotiatedConnection);
        $this->assertEquals($renegotiatedConnection, $extension->getRenegotiatedConnection());
    }

    /**
     * 测试序列化和反序列化
     */
    public function testSerializeAndDeserialize(): void
    {
        // 测试空的重协商信息
        $extension1 = new RenegotiationInfoExtension();
        $data1 = $extension1->encode();
        $decoded1 = RenegotiationInfoExtension::decode($data1);
        $this->assertEquals('', $decoded1->getRenegotiatedConnection());

        // 测试带有重协商数据的情况
        $renegotiatedConnection = random_bytes(24);
        $extension2 = new RenegotiationInfoExtension();
        $extension2->setRenegotiatedConnection($renegotiatedConnection);
        $data2 = $extension2->encode();
        $decoded2 = RenegotiationInfoExtension::decode($data2);
        $this->assertEquals($renegotiatedConnection, $decoded2->getRenegotiatedConnection());
    }

    /**
     * 测试非法数据
     */
    public function testInvalidData(): void
    {
        // 测试无效的长度前缀
        $invalidData = chr(0xFF) . random_bytes(10);
        $this->expectException(\InvalidArgumentException::class);
        RenegotiationInfoExtension::decode($invalidData);
    }

    /**
     * 测试encode方法
     */
    public function testEncode(): void
    {
        // 测试空的重协商连接
        $extension = new RenegotiationInfoExtension();
        $encoded = $extension->encode();
        $this->assertEquals(chr(0), $encoded);

        // 测试有数据的重协商连接
        $connectionData = 'test_connection_data';
        $extension->setRenegotiatedConnection($connectionData);
        $encoded = $extension->encode();

        $expectedLength = strlen($connectionData);
        $this->assertEquals(chr($expectedLength) . $connectionData, $encoded);
        $this->assertEquals($expectedLength + 1, strlen($encoded));

        // 测试更长的连接数据
        $longData = str_repeat('a', 50);
        $extension->setRenegotiatedConnection($longData);
        $encoded = $extension->encode();
        $this->assertEquals(chr(50) . $longData, $encoded);
    }
}
