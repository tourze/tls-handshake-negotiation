<?php

namespace Tourze\TLSHandshakeNegotiation\Tests\Extension;

use PHPUnit\Framework\Attributes\CoversClass;
use Tourze\PHPUnitEnum\AbstractEnumTestCase;
use Tourze\TLSHandshakeNegotiation\Extension\ExtensionType;

/**
 * TLS扩展类型枚举测试类
 *
 * @internal
 */
#[CoversClass(ExtensionType::class)]
final class ExtensionTypeTest extends AbstractEnumTestCase
{
    /**
     * 测试枚举值的存在性
     */
    public function testEnumCases(): void
    {
        $cases = ExtensionType::cases();
        $this->assertGreaterThan(0, count($cases));

        // 验证一些常见的扩展类型
        $expectedTypes = [
            'SERVER_NAME',
            'SUPPORTED_GROUPS',
            'SIGNATURE_ALGORITHMS',
            'ALPN',
            'PRE_SHARED_KEY',
            'KEY_SHARE',
            'SUPPORTED_VERSIONS',
        ];

        $caseNames = array_map(fn ($case) => $case->name, $cases);

        foreach ($expectedTypes as $type) {
            $this->assertContains($type, $caseNames);
        }
    }

    /**
     * 测试枚举值的正确性
     */
    public function testEnumValues(): void
    {
        $this->assertEquals(0, ExtensionType::SERVER_NAME->value);
        $this->assertEquals(0x000A, ExtensionType::SUPPORTED_GROUPS->value);
        $this->assertEquals(0x000D, ExtensionType::SIGNATURE_ALGORITHMS->value);
        $this->assertEquals(0x0010, ExtensionType::ALPN->value);
        $this->assertEquals(0x0029, ExtensionType::PRE_SHARED_KEY->value);
        $this->assertEquals(0x002A, ExtensionType::EARLY_DATA->value);
        $this->assertEquals(0x002B, ExtensionType::SUPPORTED_VERSIONS->value);
        $this->assertEquals(0x002C, ExtensionType::COOKIE->value);
        $this->assertEquals(0x002D, ExtensionType::PSK_KEY_EXCHANGE_MODES->value);
        $this->assertEquals(0x002F, ExtensionType::CERTIFICATE_AUTHORITIES->value);
        $this->assertEquals(0x0030, ExtensionType::OID_FILTERS->value);
        $this->assertEquals(0x0031, ExtensionType::POST_HANDSHAKE_AUTH->value);
        $this->assertEquals(0x0032, ExtensionType::SIGNATURE_ALGORITHMS_CERT->value);
        $this->assertEquals(0x0033, ExtensionType::KEY_SHARE->value);
        $this->assertEquals(0x00FF, ExtensionType::RENEGOTIATION_INFO->value);
    }

    /**
     * 测试从值创建枚举
     */
    public function testFromValue(): void
    {
        $serverName = ExtensionType::from(0);
        $this->assertEquals(ExtensionType::SERVER_NAME, $serverName);

        $keyShare = ExtensionType::from(0x0033);
        $this->assertEquals(ExtensionType::KEY_SHARE, $keyShare);

        $renegotiationInfo = ExtensionType::from(0x00FF);
        $this->assertEquals(ExtensionType::RENEGOTIATION_INFO, $renegotiationInfo);
    }

    /**
     * 测试tryFrom方法
     */
    public function testTryFrom(): void
    {
        $serverName = ExtensionType::tryFrom(0);
        $this->assertEquals(ExtensionType::SERVER_NAME, $serverName);

        // 测试无效值
        $invalid = ExtensionType::tryFrom(99999);
        $this->assertNull($invalid);
    }

    /**
     * 测试枚举名称获取
     */
    public function testEnumName(): void
    {
        $this->assertEquals('SERVER_NAME', ExtensionType::SERVER_NAME->name);
        $this->assertEquals('KEY_SHARE', ExtensionType::KEY_SHARE->name);
        $this->assertEquals('PRE_SHARED_KEY', ExtensionType::PRE_SHARED_KEY->name);
    }

    /**
     * 测试枚举比较
     */
    public function testEnumComparison(): void
    {
        $serverName1 = ExtensionType::SERVER_NAME;
        $serverName2 = ExtensionType::from(0);
        $keyShare = ExtensionType::KEY_SHARE;

        $this->assertSame($serverName1, $serverName2);
        $this->assertNotEquals($serverName1, $keyShare);
    }

    /**
     * 测试toArray()方法
     */
    public function testToArray(): void
    {
        $serverNameArray = ExtensionType::SERVER_NAME->toArray();

        $this->assertIsArray($serverNameArray);
        $this->assertCount(2, $serverNameArray);
        $this->assertArrayHasKey('value', $serverNameArray);
        $this->assertArrayHasKey('label', $serverNameArray);
        $this->assertSame(0, $serverNameArray['value']);
        $this->assertSame('SERVER_NAME', $serverNameArray['label']);

        // 测试其他类型
        $preSharedKeyArray = ExtensionType::PRE_SHARED_KEY->toArray();
        $this->assertSame(0x0029, $preSharedKeyArray['value']);
        $this->assertSame('PRE_SHARED_KEY', $preSharedKeyArray['label']);

        $keyShareArray = ExtensionType::KEY_SHARE->toArray();
        $this->assertSame(0x0033, $keyShareArray['value']);
        $this->assertSame('KEY_SHARE', $keyShareArray['label']);
    }

    /**
     * 测试toSelectItem()方法
     */
}
