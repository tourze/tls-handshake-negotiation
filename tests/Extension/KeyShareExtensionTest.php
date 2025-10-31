<?php

namespace Tourze\TLSHandshakeNegotiation\Tests\Extension;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshakeNegotiation\Extension\ExtensionType;
use Tourze\TLSHandshakeNegotiation\Extension\KeyShareEntry;
use Tourze\TLSHandshakeNegotiation\Extension\KeyShareExtension;
use Tourze\TLSHandshakeNegotiation\Extension\NamedGroup;

/**
 * 密钥共享扩展测试类
 *
 * @internal
 */
#[CoversClass(KeyShareExtension::class)]
final class KeyShareExtensionTest extends TestCase
{
    /**
     * 测试扩展类型是否正确
     */
    public function testType(): void
    {
        $extension = new KeyShareExtension();
        $this->assertEquals(ExtensionType::KEY_SHARE, $extension->getType());
    }

    /**
     * 测试设置和获取密钥共享条目
     */
    public function testSetAndGetEntries(): void
    {
        $extension = new KeyShareExtension();

        // 测试默认值
        $this->assertEmpty($extension->getEntries());

        // 创建测试条目
        $entry1 = new KeyShareEntry();
        $entry1->setGroup(NamedGroup::X25519);
        $keyExchange1 = hex2bin('abcdef1234567890');
        if (false === $keyExchange1) {
            self::fail('Failed to decode hex data for entry1');
        }
        $entry1->setKeyExchange($keyExchange1);

        $entry2 = new KeyShareEntry();
        $entry2->setGroup(NamedGroup::SECP256R1);
        $keyExchange2 = hex2bin('1122334455667788');
        if (false === $keyExchange2) {
            self::fail('Failed to decode hex data for entry2');
        }
        $entry2->setKeyExchange($keyExchange2);

        // 测试设置条目
        $entries = [$entry1, $entry2];
        $extension->setEntries($entries);
        $this->assertEquals($entries, $extension->getEntries());

        // 测试添加条目
        $extension = new KeyShareExtension();
        $extension->addEntry($entry1);
        $this->assertCount(1, $extension->getEntries());
        $this->assertEquals($entry1, $extension->getEntries()[0]);
    }

    /**
     * 测试扩展的编码和解码
     */
    public function testEncodeAndDecode(): void
    {
        $originalExtension = new KeyShareExtension();

        // 创建条目
        $entry = new KeyShareEntry();
        $entry->setGroup(NamedGroup::X25519);
        $keyExchange = hex2bin('01020304');
        if (false === $keyExchange) {
            self::fail('Failed to decode hex data');
        }
        $entry->setKeyExchange($keyExchange);

        $originalExtension->addEntry($entry);

        // 编码
        $encodedData = $originalExtension->encode();
        $this->assertNotEmpty($encodedData);

        // 解码
        $decodedExtension = KeyShareExtension::decode($encodedData);

        // 验证解码后的扩展
        $this->assertCount(1, $decodedExtension->getEntries());
        $decodedEntry = $decodedExtension->getEntries()[0];
        $this->assertEquals(NamedGroup::X25519->value, $decodedEntry->getGroup());
        $expectedKeyExchange = hex2bin('01020304');
        if (false === $expectedKeyExchange) {
            self::fail('Failed to decode expected hex data');
        }
        $this->assertEquals($expectedKeyExchange, $decodedEntry->getKeyExchange());
    }

    /**
     * 测试编码格式是否符合RFC规范
     */
    public function testEncodeFormat(): void
    {
        $extension = new KeyShareExtension();

        // 创建条目
        $entry = new KeyShareEntry();
        $entry->setGroup(NamedGroup::X25519);
        $keyExchange = hex2bin('0102');
        if (false === $keyExchange) {
            self::fail('Failed to decode hex data');
        }
        $entry->setKeyExchange($keyExchange);

        $extension->addEntry($entry);

        $encoded = $extension->encode();

        // 客户端扩展数据应为：
        // - 2字节的条目列表长度 (0006) - 6字节，一个条目
        // - 2字节的组标识符 (001d) - X25519
        // - 2字节的密钥交换数据长度 (0002) - 2字节
        // - 密钥交换数据 (0102)
        $part1 = hex2bin('0006');
        $part2 = hex2bin('001d');
        $part3 = hex2bin('0002');
        $part4 = hex2bin('0102');
        if (false === $part1 || false === $part2 || false === $part3 || false === $part4) {
            self::fail('Failed to decode hex data for expected value');
        }
        $expected = $part1 . $part2 . $part3 . $part4;

        $this->assertEquals($expected, $encoded);
    }

    /**
     * 测试服务器格式的扩展
     */
    public function testServerFormat(): void
    {
        $extension = new KeyShareExtension(true); // 服务器格式

        // 创建条目
        $entry = new KeyShareEntry();
        $entry->setGroup(NamedGroup::X25519);
        $keyExchange = hex2bin('0102');
        if (false === $keyExchange) {
            self::fail('Failed to decode hex data');
        }
        $entry->setKeyExchange($keyExchange);

        $extension->addEntry($entry);

        $encoded = $extension->encode();

        // 服务器扩展数据应为：
        // - 2字节的组标识符 (001d) - X25519
        // - 2字节的密钥交换数据长度 (0002) - 2字节
        // - 密钥交换数据 (0102)
        $part1 = hex2bin('001d');
        $part2 = hex2bin('0002');
        $part3 = hex2bin('0102');
        if (false === $part1 || false === $part2 || false === $part3) {
            self::fail('Failed to decode hex data for expected value');
        }
        $expected = $part1 . $part2 . $part3;

        $this->assertEquals($expected, $encoded);

        // 测试解码
        $decodedExtension = KeyShareExtension::decode($encoded, true);
        $this->assertTrue($decodedExtension->isServerFormat());
        $this->assertCount(1, $decodedExtension->getEntries());
    }

    /**
     * 测试解码无效数据时的异常处理
     */
    public function testDecodeInvalidData(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        // 创建无效的数据 (长度字段表示有6个字节的数据，但实际只有4个字节)
        $part1 = hex2bin('0006');
        $part2 = hex2bin('001d0000');
        if (false === $part1 || false === $part2) {
            self::fail('Failed to decode hex data for invalid test data');
        }
        $invalidData = $part1 . $part2;

        KeyShareExtension::decode($invalidData);
    }

    /**
     * 测试TLS版本兼容性
     */
    public function testVersionCompatibility(): void
    {
        $extension = new KeyShareExtension();

        // 此扩展仅适用于TLS 1.3
        $this->assertFalse($extension->isApplicableForVersion('1.2'));
        $this->assertTrue($extension->isApplicableForVersion('1.3'));
    }

    /**
     * 测试通过组获取条目
     */
    public function testGetEntryByGroup(): void
    {
        $extension = new KeyShareExtension();

        // 创建测试条目
        $entry1 = new KeyShareEntry();
        $entry1->setGroup(NamedGroup::X25519);
        $keyExchange1 = hex2bin('01020304');
        if (false === $keyExchange1) {
            self::fail('Failed to decode hex data for entry1');
        }
        $entry1->setKeyExchange($keyExchange1);

        $entry2 = new KeyShareEntry();
        $entry2->setGroup(NamedGroup::SECP256R1);
        $keyExchange2 = hex2bin('05060708');
        if (false === $keyExchange2) {
            self::fail('Failed to decode hex data for entry2');
        }
        $entry2->setKeyExchange($keyExchange2);

        $extension->addEntry($entry1);
        $extension->addEntry($entry2);

        // 测试获取存在的条目
        $retrievedEntry = $extension->getEntryByGroup(NamedGroup::X25519);
        $this->assertNotNull($retrievedEntry);
        $expectedKeyExchange = hex2bin('01020304');
        if (false === $expectedKeyExchange) {
            self::fail('Failed to decode expected hex data');
        }
        $this->assertEquals($expectedKeyExchange, $retrievedEntry->getKeyExchange());

        // 测试获取不存在的条目
        $this->assertNull($extension->getEntryByGroup(NamedGroup::SECP521R1));
    }

    /**
     * 测试addEntry方法
     */
    public function testAddEntry(): void
    {
        $extension = new KeyShareExtension();
        $this->assertEmpty($extension->getEntries());

        // 添加第一个条目
        $entry1 = new KeyShareEntry();
        $entry1->setGroup(NamedGroup::X25519);
        $keyExchange1 = hex2bin('01020304');
        if (false === $keyExchange1) {
            self::fail('Failed to decode hex data for entry1');
        }
        $entry1->setKeyExchange($keyExchange1);

        $result = $extension->addEntry($entry1);
        $this->assertSame($extension, $result); // 测试流式接口
        $this->assertCount(1, $extension->getEntries());
        $this->assertSame($entry1, $extension->getEntries()[0]);

        // 添加第二个条目
        $entry2 = new KeyShareEntry();
        $entry2->setGroup(NamedGroup::SECP256R1);
        $keyExchange2 = hex2bin('05060708');
        if (false === $keyExchange2) {
            self::fail('Failed to decode hex data for entry2');
        }
        $entry2->setKeyExchange($keyExchange2);

        $extension->addEntry($entry2);
        $this->assertCount(2, $extension->getEntries());
        $this->assertSame($entry1, $extension->getEntries()[0]);
        $this->assertSame($entry2, $extension->getEntries()[1]);
    }
}
