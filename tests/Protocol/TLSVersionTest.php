<?php

namespace Tourze\TLSHandshakeNegotiation\Tests\Protocol;

use PHPUnit\Framework\Attributes\CoversClass;
use Tourze\PHPUnitEnum\AbstractEnumTestCase;
use Tourze\TLSHandshakeNegotiation\Protocol\TLSVersion;

/**
 * TLSVersion枚举测试
 *
 * @internal
 */
#[CoversClass(TLSVersion::class)]
final class TLSVersionTest extends AbstractEnumTestCase
{
    /**
     * 测试版本值
     */
    public function testVersionValues(): void
    {
        $this->assertEquals(0x0300, TLSVersion::SSL_3_0->value);
        $this->assertEquals(0x0301, TLSVersion::TLS_1_0->value);
        $this->assertEquals(0x0302, TLSVersion::TLS_1_1->value);
        $this->assertEquals(0x0303, TLSVersion::TLS_1_2->value);
        $this->assertEquals(0x0304, TLSVersion::TLS_1_3->value);
    }

    /**
     * 测试获取版本名称
     */
    public function testGetName(): void
    {
        $this->assertEquals('SSL 3.0', TLSVersion::SSL_3_0->getName());
        $this->assertEquals('TLS 1.0', TLSVersion::TLS_1_0->getName());
        $this->assertEquals('TLS 1.1', TLSVersion::TLS_1_1->getName());
        $this->assertEquals('TLS 1.2', TLSVersion::TLS_1_2->getName());
        $this->assertEquals('TLS 1.3', TLSVersion::TLS_1_3->getName());
    }

    /**
     * 测试判断版本是否安全
     */
    public function testIsSecure(): void
    {
        $this->assertFalse(TLSVersion::SSL_3_0->isSecure());
        $this->assertFalse(TLSVersion::TLS_1_0->isSecure());
        $this->assertFalse(TLSVersion::TLS_1_1->isSecure());
        $this->assertTrue(TLSVersion::TLS_1_2->isSecure());
        $this->assertTrue(TLSVersion::TLS_1_3->isSecure());
    }

    /**
     * 测试获取版本名称（静态方法）
     */
    public function testGetVersionName(): void
    {
        $this->assertEquals('TLS 1.2', TLSVersion::getVersionName(0x0303));
        $this->assertEquals('Unknown (0x0305)', TLSVersion::getVersionName(0x0305));
    }

    /**
     * 测试获取推荐的版本列表
     */
    public function testGetRecommendedVersions(): void
    {
        $versions = TLSVersion::getRecommendedVersions();

        $this->assertCount(2, $versions);
        $this->assertEquals(TLSVersion::TLS_1_3, $versions[0]);
        $this->assertEquals(TLSVersion::TLS_1_2, $versions[1]);
    }

    /**
     * 测试toArray方法
     */
    public function testToArray(): void
    {
        $ssl30Array = TLSVersion::SSL_3_0->toArray();
        $this->assertSame(0x0300, $ssl30Array['value'], 'SSL_3_0的value应为0x0300');
        $this->assertSame('SSL_3_0', $ssl30Array['label'], 'SSL_3_0的label应为SSL_3_0');

        $tls10Array = TLSVersion::TLS_1_0->toArray();
        $this->assertSame(0x0301, $tls10Array['value'], 'TLS_1_0的value应为0x0301');
        $this->assertSame('TLS_1_0', $tls10Array['label'], 'TLS_1_0的label应为TLS_1_0');

        $tls11Array = TLSVersion::TLS_1_1->toArray();
        $this->assertSame(0x0302, $tls11Array['value'], 'TLS_1_1的value应为0x0302');
        $this->assertSame('TLS_1_1', $tls11Array['label'], 'TLS_1_1的label应为TLS_1_1');

        $tls12Array = TLSVersion::TLS_1_2->toArray();
        $this->assertSame(0x0303, $tls12Array['value'], 'TLS_1_2的value应为0x0303');
        $this->assertSame('TLS_1_2', $tls12Array['label'], 'TLS_1_2的label应为TLS_1_2');

        $tls13Array = TLSVersion::TLS_1_3->toArray();
        $this->assertSame(0x0304, $tls13Array['value'], 'TLS_1_3的value应为0x0304');
        $this->assertSame('TLS_1_3', $tls13Array['label'], 'TLS_1_3的label应为TLS_1_3');
    }

    /**
     * 测试toSelectItem方法
     */
}
