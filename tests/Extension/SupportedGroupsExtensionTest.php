<?php

namespace Tourze\TLSHandshakeNegotiation\Tests\Extension;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshakeNegotiation\Extension\ExtensionType;
use Tourze\TLSHandshakeNegotiation\Extension\NamedGroup;
use Tourze\TLSHandshakeNegotiation\Extension\SupportedGroupsExtension;

/**
 * SupportedGroupsExtension 类测试
 *
 * @internal
 */
#[CoversClass(SupportedGroupsExtension::class)]
final class SupportedGroupsExtensionTest extends TestCase
{
    /**
     * 测试默认构造函数
     */
    public function testDefaultConstructor(): void
    {
        $extension = new SupportedGroupsExtension();
        $this->assertNotEmpty($extension->getGroups());
        $this->assertEquals(ExtensionType::SUPPORTED_GROUPS, $extension->getType());
    }

    /**
     * 测试自定义组构造函数
     */
    public function testCustomGroupsConstructor(): void
    {
        $customGroups = [
            NamedGroup::X25519,
            NamedGroup::SECP256R1,
        ];

        $extension = new SupportedGroupsExtension($customGroups);
        $this->assertCount(2, $extension->getGroups());
        $this->assertSame($customGroups, $extension->getGroups());
    }

    /**
     * 测试获取和设置组
     */
    public function testGetAndSetGroups(): void
    {
        $extension = new SupportedGroupsExtension();
        $originalGroups = $extension->getGroups();

        $newGroups = [NamedGroup::SECP384R1, NamedGroup::FFDHE2048];
        $extension->setGroups($newGroups);

        $this->assertNotSame($originalGroups, $extension->getGroups());
        $this->assertSame($newGroups, $extension->getGroups());
    }

    /**
     * 测试添加组
     */
    public function testAddGroup(): void
    {
        $extension = new SupportedGroupsExtension([]);
        $this->assertEmpty($extension->getGroups());

        $extension->addGroup(NamedGroup::X25519);
        $this->assertCount(1, $extension->getGroups());
        $this->assertContains(NamedGroup::X25519, $extension->getGroups());

        // 测试添加重复的组
        $extension->addGroup(NamedGroup::X25519);
        $this->assertCount(1, $extension->getGroups());

        $extension->addGroup(NamedGroup::SECP256R1);
        $this->assertCount(2, $extension->getGroups());
        $this->assertContains(NamedGroup::SECP256R1, $extension->getGroups());
    }

    /**
     * 测试移除组
     */
    public function testRemoveGroup(): void
    {
        $groups = [
            NamedGroup::X25519,
            NamedGroup::SECP256R1,
            NamedGroup::FFDHE2048,
        ];

        $extension = new SupportedGroupsExtension($groups);
        $this->assertCount(3, $extension->getGroups());

        $extension->removeGroup(NamedGroup::SECP256R1);
        $this->assertCount(2, $extension->getGroups());
        $this->assertNotContains(NamedGroup::SECP256R1, $extension->getGroups());
        $this->assertContains(NamedGroup::X25519, $extension->getGroups());
        $this->assertContains(NamedGroup::FFDHE2048, $extension->getGroups());
    }

    /**
     * 测试获取椭圆曲线组
     */
    public function testGetECGroups(): void
    {
        $groups = [
            NamedGroup::X25519,
            NamedGroup::SECP256R1,
            NamedGroup::FFDHE2048,
            NamedGroup::FFDHE3072,
        ];

        $extension = new SupportedGroupsExtension($groups);
        $ecGroups = $extension->getECGroups();

        $this->assertCount(2, $ecGroups);
        $this->assertContains(NamedGroup::X25519, $ecGroups);
        $this->assertContains(NamedGroup::SECP256R1, $ecGroups);
        $this->assertNotContains(NamedGroup::FFDHE2048, $ecGroups);
        $this->assertNotContains(NamedGroup::FFDHE3072, $ecGroups);
    }

    /**
     * 测试获取DHE组
     */
    public function testGetDHEGroups(): void
    {
        $groups = [
            NamedGroup::X25519,
            NamedGroup::SECP256R1,
            NamedGroup::FFDHE2048,
            NamedGroup::FFDHE3072,
        ];

        $extension = new SupportedGroupsExtension($groups);
        $dheGroups = $extension->getDHEGroups();

        $this->assertCount(2, $dheGroups);
        $this->assertContains(NamedGroup::FFDHE2048, $dheGroups);
        $this->assertContains(NamedGroup::FFDHE3072, $dheGroups);
        $this->assertNotContains(NamedGroup::X25519, $dheGroups);
        $this->assertNotContains(NamedGroup::SECP256R1, $dheGroups);
    }

    /**
     * 测试协商逻辑
     */
    public function testNegotiate(): void
    {
        // 服务器支持的组
        $serverGroups = [
            NamedGroup::X25519,
            NamedGroup::SECP256R1,
            NamedGroup::SECP384R1,
            NamedGroup::FFDHE2048,
        ];
        $serverExtension = new SupportedGroupsExtension($serverGroups);

        // 客户端支持的组（优先级不同）
        $clientGroups = [
            NamedGroup::SECP256R1, // 优先级1
            NamedGroup::FFDHE2048, // 优先级2
            NamedGroup::X25519,     // 优先级3
        ];
        $clientExtension = new SupportedGroupsExtension($clientGroups);

        // 服务器协商结果（应该按照客户端优先级排序）
        $negotiatedGroups = $serverExtension->negotiate($clientExtension);

        $this->assertCount(3, $negotiatedGroups);
        $this->assertSame(NamedGroup::SECP256R1, $negotiatedGroups[0]);
        $this->assertSame(NamedGroup::FFDHE2048, $negotiatedGroups[1]);
        $this->assertSame(NamedGroup::X25519, $negotiatedGroups[2]);

        // 部分不兼容的情况
        $limitedClientGroups = [
            NamedGroup::SECP256R1,
            NamedGroup::SECP521R1, // 服务器不支持
        ];
        $limitedClientExtension = new SupportedGroupsExtension($limitedClientGroups);

        $limitedNegotiatedGroups = $serverExtension->negotiate($limitedClientExtension);

        $this->assertCount(1, $limitedNegotiatedGroups);
        $this->assertSame(NamedGroup::SECP256R1, $limitedNegotiatedGroups[0]);
    }

    /**
     * 测试encode方法
     */
    public function testEncode(): void
    {
        // 测试空的组列表
        $emptyExtension = new SupportedGroupsExtension([]);
        $emptyEncoded = $emptyExtension->encode();
        $this->assertEquals(2, strlen($emptyEncoded)); // 只有2字节的长度字段
        $this->assertEquals("\x00\x00", $emptyEncoded);

        // 测试单个组
        $singleExtension = new SupportedGroupsExtension([NamedGroup::X25519]);
        $singleEncoded = $singleExtension->encode();
        $this->assertEquals(4, strlen($singleEncoded)); // 2字节长度 + 2字节组值

        // 验证编码格式：长度(0x0002) + X25519值(0x001D)
        $expected = "\x00\x02\x00\x1D";
        $this->assertEquals($expected, $singleEncoded);

        // 测试多个组
        $multiExtension = new SupportedGroupsExtension([
            NamedGroup::X25519,     // 0x001D
            NamedGroup::SECP256R1,  // 0x0017
            NamedGroup::FFDHE2048,   // 0x0100
        ]);
        $multiEncoded = $multiExtension->encode();
        $this->assertEquals(8, strlen($multiEncoded)); // 2字节长度 + 3*2字节组值

        // 验证编码格式：长度(0x0006) + 三个组值
        $expectedMulti = "\x00\x06\x00\x1D\x00\x17\x01\x00";
        $this->assertEquals($expectedMulti, $multiEncoded);
    }
}
