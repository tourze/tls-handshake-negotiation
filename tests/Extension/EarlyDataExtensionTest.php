<?php

namespace Tourze\TLSHandshakeNegotiation\Tests\Extension;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshakeNegotiation\Extension\EarlyDataExtension;
use Tourze\TLSHandshakeNegotiation\Extension\ExtensionType;

/**
 * 早期数据扩展测试类
 *
 * @internal
 */
#[CoversClass(EarlyDataExtension::class)]
final class EarlyDataExtensionTest extends TestCase
{
    /**
     * 测试扩展类型是否正确
     */
    public function testType(): void
    {
        $extension = new EarlyDataExtension();
        $this->assertEquals(ExtensionType::EARLY_DATA, $extension->getType());
    }

    /**
     * 测试客户端格式的编码和解码
     */
    public function testClientEncodeAndDecode(): void
    {
        $originalExtension = new EarlyDataExtension();

        // 编码
        $encodedData = $originalExtension->encode();
        $this->assertEmpty($encodedData);

        // 解码
        $decodedExtension = EarlyDataExtension::decode($encodedData);
        $this->assertInstanceOf(EarlyDataExtension::class, $decodedExtension);
    }

    /**
     * 测试服务器格式的编码和解码
     */
    public function testServerEncodeAndDecode(): void
    {
        $originalExtension = new EarlyDataExtension(EarlyDataExtension::FORMAT_SERVER_HELLO);

        // 编码
        $encodedData = $originalExtension->encode();
        $this->assertEmpty($encodedData);

        // 解码
        $decodedExtension = EarlyDataExtension::decode($encodedData, EarlyDataExtension::FORMAT_SERVER_HELLO);
        $this->assertInstanceOf(EarlyDataExtension::class, $decodedExtension);
        $this->assertEquals(EarlyDataExtension::FORMAT_SERVER_HELLO, $decodedExtension->getFormat());
    }

    /**
     * 测试New Session Ticket格式的编码和解码
     */
    public function testNewSessionTicketEncodeAndDecode(): void
    {
        $originalExtension = new EarlyDataExtension(EarlyDataExtension::FORMAT_NEW_SESSION_TICKET);
        $originalExtension->setMaxEarlyDataSize(12345);

        // 编码
        $encodedData = $originalExtension->encode();
        $this->assertNotEmpty($encodedData);

        // 解码
        $decodedExtension = EarlyDataExtension::decode($encodedData, EarlyDataExtension::FORMAT_NEW_SESSION_TICKET);

        // 验证解码后的扩展
        $this->assertEquals(EarlyDataExtension::FORMAT_NEW_SESSION_TICKET, $decodedExtension->getFormat());
        $this->assertEquals(12345, $decodedExtension->getMaxEarlyDataSize());
    }

    /**
     * 测试New Session Ticket格式的编码格式是否符合RFC规范
     */
    public function testNewSessionTicketEncodeFormat(): void
    {
        $extension = new EarlyDataExtension(EarlyDataExtension::FORMAT_NEW_SESSION_TICKET);
        $extension->setMaxEarlyDataSize(12345);

        $encoded = $extension->encode();

        // 扩展数据应为：
        // - 4字节的最大早期数据大小 (00003039) - 12345
        $expected = hex2bin('00003039');

        $this->assertEquals($expected, $encoded);
    }

    /**
     * 测试解码无效数据时的异常处理
     */
    public function testDecodeInvalidData(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        // 创建无效的数据 (New Session Ticket格式需要4字节的数据，但只有3个字节)
        $invalidData = hex2bin('000030');
        if (false === $invalidData) {
            self::fail('Failed to decode hex data');
        }

        EarlyDataExtension::decode($invalidData, EarlyDataExtension::FORMAT_NEW_SESSION_TICKET);
    }

    /**
     * 测试TLS版本兼容性
     */
    public function testVersionCompatibility(): void
    {
        $extension = new EarlyDataExtension();

        // 此扩展仅适用于TLS 1.3
        $this->assertFalse($extension->isApplicableForVersion('1.2'));
        $this->assertTrue($extension->isApplicableForVersion('1.3'));
    }

    /**
     * 测试encode方法
     */
    public function testEncode(): void
    {
        // 测试客户端Hello格式
        $clientExtension = new EarlyDataExtension(EarlyDataExtension::FORMAT_CLIENT_HELLO);
        $this->assertEmpty($clientExtension->encode());

        // 测试服务器Hello格式
        $serverExtension = new EarlyDataExtension(EarlyDataExtension::FORMAT_SERVER_HELLO);
        $this->assertEmpty($serverExtension->encode());

        // 测试加密扩展格式
        $encryptedExtension = new EarlyDataExtension(EarlyDataExtension::FORMAT_ENCRYPTED_EXTENSIONS);
        $this->assertEmpty($encryptedExtension->encode());

        // 测试新会话票据格式
        $ticketExtension = new EarlyDataExtension(EarlyDataExtension::FORMAT_NEW_SESSION_TICKET);
        $ticketExtension->setMaxEarlyDataSize(8192);
        $encoded = $ticketExtension->encode();
        $this->assertEquals(4, strlen($encoded));
        $this->assertEquals(pack('N', 8192), $encoded);
    }
}
