<?php

namespace Tourze\TLSHandshakeNegotiation\Tests\Extension;

use PHPUnit\Framework\Attributes\CoversClass;
use Tourze\PHPUnitEnum\AbstractEnumTestCase;
use Tourze\TLSHandshakeNegotiation\Extension\NamedGroup;

/**
 * NamedGroup 枚举测试
 *
 * @internal
 */
#[CoversClass(NamedGroup::class)]
final class NamedGroupTest extends AbstractEnumTestCase
{
    /**
     * 测试组值常量
     */
    public function testGroupValues(): void
    {
        $this->assertEquals(0x0017, NamedGroup::SECP256R1->value);
        $this->assertEquals(0x0018, NamedGroup::SECP384R1->value);
        $this->assertEquals(0x0019, NamedGroup::SECP521R1->value);
        $this->assertEquals(0x001D, NamedGroup::X25519->value);
        $this->assertEquals(0x001E, NamedGroup::X448->value);
        $this->assertEquals(0x0100, NamedGroup::FFDHE2048->value);
        $this->assertEquals(0x0101, NamedGroup::FFDHE3072->value);
        $this->assertEquals(0x0102, NamedGroup::FFDHE4096->value);
        $this->assertEquals(0x0103, NamedGroup::FFDHE6144->value);
        $this->assertEquals(0x0104, NamedGroup::FFDHE8192->value);
    }

    /**
     * 测试获取名称方法
     */
    public function testGetName(): void
    {
        $this->assertEquals('secp256r1', NamedGroup::SECP256R1->getName());
        $this->assertEquals('secp384r1', NamedGroup::SECP384R1->getName());
        $this->assertEquals('secp521r1', NamedGroup::SECP521R1->getName());
        $this->assertEquals('x25519', NamedGroup::X25519->getName());
        $this->assertEquals('x448', NamedGroup::X448->getName());
        $this->assertEquals('ffdhe2048', NamedGroup::FFDHE2048->getName());
        $this->assertEquals('ffdhe3072', NamedGroup::FFDHE3072->getName());
        $this->assertEquals('ffdhe4096', NamedGroup::FFDHE4096->getName());
        $this->assertEquals('ffdhe6144', NamedGroup::FFDHE6144->getName());
        $this->assertEquals('ffdhe8192', NamedGroup::FFDHE8192->getName());
    }

    /**
     * 测试是否为EC组
     */
    public function testIsECGroup(): void
    {
        $this->assertTrue(NamedGroup::SECP256R1->isECGroup());
        $this->assertTrue(NamedGroup::SECP384R1->isECGroup());
        $this->assertTrue(NamedGroup::SECP521R1->isECGroup());
        $this->assertTrue(NamedGroup::X25519->isECGroup());
        $this->assertTrue(NamedGroup::X448->isECGroup());

        $this->assertFalse(NamedGroup::FFDHE2048->isECGroup());
        $this->assertFalse(NamedGroup::FFDHE3072->isECGroup());
        $this->assertFalse(NamedGroup::FFDHE4096->isECGroup());
        $this->assertFalse(NamedGroup::FFDHE6144->isECGroup());
        $this->assertFalse(NamedGroup::FFDHE8192->isECGroup());
    }

    /**
     * 测试是否为DHE组
     */
    public function testIsDHEGroup(): void
    {
        $this->assertFalse(NamedGroup::SECP256R1->isDHEGroup());
        $this->assertFalse(NamedGroup::SECP384R1->isDHEGroup());
        $this->assertFalse(NamedGroup::SECP521R1->isDHEGroup());
        $this->assertFalse(NamedGroup::X25519->isDHEGroup());
        $this->assertFalse(NamedGroup::X448->isDHEGroup());

        $this->assertTrue(NamedGroup::FFDHE2048->isDHEGroup());
        $this->assertTrue(NamedGroup::FFDHE3072->isDHEGroup());
        $this->assertTrue(NamedGroup::FFDHE4096->isDHEGroup());
        $this->assertTrue(NamedGroup::FFDHE6144->isDHEGroup());
        $this->assertTrue(NamedGroup::FFDHE8192->isDHEGroup());
    }

    /**
     * 测试获取推荐组
     */
    public function testGetRecommendedGroups(): void
    {
        // TLS 1.3
        $tls13Groups = NamedGroup::getRecommendedGroups(0x0304);
        $this->assertNotEmpty($tls13Groups);
        $this->assertContains(NamedGroup::X25519, $tls13Groups);
        $this->assertContains(NamedGroup::SECP256R1, $tls13Groups);

        // TLS 1.2
        $tls12Groups = NamedGroup::getRecommendedGroups(0x0303);
        $this->assertNotEmpty($tls12Groups);
        $this->assertContains(NamedGroup::SECP256R1, $tls12Groups);
    }

    /**
     * 测试获取密钥长度
     */
    public function testGetKeyLength(): void
    {
        $this->assertEquals(32, NamedGroup::SECP256R1->getKeyLength());
        $this->assertEquals(48, NamedGroup::SECP384R1->getKeyLength());
        $this->assertEquals(66, NamedGroup::SECP521R1->getKeyLength());
        $this->assertEquals(32, NamedGroup::X25519->getKeyLength());
        $this->assertEquals(56, NamedGroup::X448->getKeyLength());
        $this->assertEquals(256, NamedGroup::FFDHE2048->getKeyLength());
        $this->assertEquals(384, NamedGroup::FFDHE3072->getKeyLength());
        $this->assertEquals(512, NamedGroup::FFDHE4096->getKeyLength());
        $this->assertEquals(768, NamedGroup::FFDHE6144->getKeyLength());
        $this->assertEquals(1024, NamedGroup::FFDHE8192->getKeyLength());
    }

    /**
     * 测试toArray方法
     */
    public function testToArray(): void
    {
        $result = NamedGroup::X25519->toArray();
        $this->assertIsArray($result);
        $this->assertArrayHasKey('value', $result);
        $this->assertArrayHasKey('label', $result);
        $this->assertEquals(NamedGroup::X25519->value, $result['value']);
        $this->assertEquals(NamedGroup::X25519->getLabel(), $result['label']);
    }

    /**
     * 测试toSelectItem方法
     */
}
