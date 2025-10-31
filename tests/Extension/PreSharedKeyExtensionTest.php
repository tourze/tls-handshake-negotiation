<?php

declare(strict_types=1);

namespace Tourze\TLSHandshakeNegotiation\Extension;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
#[CoversClass(PreSharedKeyExtension::class)]
final class PreSharedKeyExtensionTest extends TestCase
{
    public function testGetType(): void
    {
        $extension = new PreSharedKeyExtension();
        $this->assertSame(ExtensionType::PRE_SHARED_KEY, $extension->getType());
    }

    public function testClientFormat(): void
    {
        $extension = new PreSharedKeyExtension(false);
        $this->assertFalse($extension->isServerFormat());

        $identity = new PSKIdentity();
        $identity->setIdentity('test_identity');
        $identity->setObfuscatedTicketAge(123456);

        $extension->addIdentity($identity);
        $extension->addBinder('test_binder_value');

        $this->assertCount(1, $extension->getIdentities());
        $this->assertCount(1, $extension->getBinders());
    }

    public function testServerFormat(): void
    {
        $extension = new PreSharedKeyExtension(true);
        $this->assertTrue($extension->isServerFormat());

        $extension->setSelectedIdentity(2);
        $this->assertSame(2, $extension->getSelectedIdentity());
    }

    public function testEncodeDecode(): void
    {
        // Test server format
        $serverExt = new PreSharedKeyExtension(true);
        $serverExt->setSelectedIdentity(5);

        $encoded = $serverExt->encode();
        $decoded = PreSharedKeyExtension::decode($encoded, true);

        $this->assertTrue($decoded->isServerFormat());
        $this->assertSame(5, $decoded->getSelectedIdentity());
    }

    public function testIsApplicableForVersion(): void
    {
        $extension = new PreSharedKeyExtension();

        $this->assertTrue($extension->isApplicableForVersion('1.3'));
        $this->assertFalse($extension->isApplicableForVersion('1.2'));
        $this->assertFalse($extension->isApplicableForVersion('1.1'));
    }

    /**
     * 测试addBinder()方法
     */
    public function testAddBinder(): void
    {
        $extension = new PreSharedKeyExtension(false);

        // 初始状态应该没有绑定器
        $this->assertCount(0, $extension->getBinders());

        // 添加第一个绑定器
        $binder1 = 'test_binder_1';
        $extension->addBinder($binder1);

        $binders = $extension->getBinders();
        $this->assertCount(1, $binders);
        $this->assertContains($binder1, $binders);
        $this->assertSame($binder1, $binders[0]);

        // 添加第二个绑定器
        $binder2 = 'test_binder_2';
        $extension->addBinder($binder2);

        $binders = $extension->getBinders();
        $this->assertCount(2, $binders);
        $this->assertContains($binder1, $binders);
        $this->assertContains($binder2, $binders);
        $this->assertSame($binder1, $binders[0]);
        $this->assertSame($binder2, $binders[1]);

        // 添加空字符串绑定器
        $extension->addBinder('');
        $binders = $extension->getBinders();
        $this->assertCount(3, $binders);
        $this->assertSame('', $binders[2]);

        // 测试方法链式调用
        $result = $extension->addBinder('chained_binder');
        $this->assertSame($extension, $result);
        $this->assertCount(4, $extension->getBinders());
    }

    /**
     * 测试addIdentity()方法
     */
    public function testAddIdentity(): void
    {
        $extension = new PreSharedKeyExtension(false);

        // 初始状态应该没有身份标识
        $this->assertCount(0, $extension->getIdentities());

        // 创建并添加第一个身份标识
        $identity1 = new PSKIdentity();
        $identity1->setIdentity('test_identity_1');
        $identity1->setObfuscatedTicketAge(12345);

        $extension->addIdentity($identity1);

        $identities = $extension->getIdentities();
        $this->assertCount(1, $identities);
        $this->assertContains($identity1, $identities);
        $this->assertSame($identity1, $identities[0]);
        $this->assertSame('test_identity_1', $identities[0]->getIdentity());
        $this->assertSame(12345, $identities[0]->getObfuscatedTicketAge());

        // 创建并添加第二个身份标识
        $identity2 = new PSKIdentity();
        $identity2->setIdentity('test_identity_2');
        $identity2->setObfuscatedTicketAge(67890);

        $extension->addIdentity($identity2);

        $identities = $extension->getIdentities();
        $this->assertCount(2, $identities);
        $this->assertContains($identity1, $identities);
        $this->assertContains($identity2, $identities);
        $this->assertSame($identity1, $identities[0]);
        $this->assertSame($identity2, $identities[1]);

        // 创建并添加空标识的身份
        $identity3 = new PSKIdentity();
        $identity3->setIdentity('');
        $identity3->setObfuscatedTicketAge(0);

        $extension->addIdentity($identity3);
        $identities = $extension->getIdentities();
        $this->assertCount(3, $identities);
        $this->assertSame('', $identities[2]->getIdentity());
        $this->assertSame(0, $identities[2]->getObfuscatedTicketAge());

        // 测试方法链式调用
        $identity4 = new PSKIdentity();
        $identity4->setIdentity('chained_identity');
        $identity4->setObfuscatedTicketAge(999);

        $result = $extension->addIdentity($identity4);
        $this->assertSame($extension, $result);
        $this->assertCount(4, $extension->getIdentities());
    }
}
