<?php

namespace Tourze\TLSHandshakeNegotiation\Tests\Config;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshakeNegotiation\Config\HandshakeConfig;

/**
 * @internal
 */
#[CoversClass(HandshakeConfig::class)]
final class HandshakeConfigTest extends TestCase
{
    /**
     * 测试握手配置的基本功能
     */
    public function testBasicConfiguration(): void
    {
        $config = new HandshakeConfig();

        // 测试默认值
        $this->assertFalse($config->isServerMode());
        $this->assertEquals(['TLS 1.2', 'TLS 1.3'], $config->getSupportedVersions());

        // 测试设置和获取服务器模式
        $config->setServerMode(true);
        $this->assertTrue($config->isServerMode());

        // 测试设置和获取支持的版本
        $config->setSupportedVersions(['TLS 1.2']);
        $this->assertEquals(['TLS 1.2'], $config->getSupportedVersions());
    }

    /**
     * 测试加密套件配置
     */
    public function testCipherSuiteConfiguration(): void
    {
        $config = new HandshakeConfig();

        // 默认应该有一些加密套件
        $this->assertNotEmpty($config->getSupportedCipherSuites());

        // 测试设置和获取支持的加密套件
        $suites = ['TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256'];
        $config->setSupportedCipherSuites($suites);
        $this->assertEquals($suites, $config->getSupportedCipherSuites());
    }

    /**
     * 测试证书配置
     */
    public function testCertificateConfiguration(): void
    {
        $config = new HandshakeConfig();

        // 默认没有证书路径
        $this->assertNull($config->getCertificatePath());

        // 测试设置和获取证书路径
        $config->setCertificatePath('/path/to/cert.pem');
        $this->assertEquals('/path/to/cert.pem', $config->getCertificatePath());

        // 测试设置和获取私钥路径
        $config->setPrivateKeyPath('/path/to/key.pem');
        $this->assertEquals('/path/to/key.pem', $config->getPrivateKeyPath());
    }

    /**
     * 测试扩展配置
     */
    public function testExtensionConfiguration(): void
    {
        $config = new HandshakeConfig();

        // 测试启用的扩展
        $config->enableExtension('signature_algorithms');
        $this->assertTrue($config->isExtensionEnabled('signature_algorithms'));

        // 测试禁用的扩展
        $config->disableExtension('signature_algorithms');
        $this->assertFalse($config->isExtensionEnabled('signature_algorithms'));
    }

    /**
     * 测试禁用扩展功能
     */
    public function testDisableExtension(): void
    {
        $config = new HandshakeConfig();

        // 测试禁用默认启用的扩展
        $this->assertTrue($config->isExtensionEnabled('server_name'));
        $config->disableExtension('server_name');
        $this->assertFalse($config->isExtensionEnabled('server_name'));

        // 测试禁用默认禁用的扩展
        $this->assertFalse($config->isExtensionEnabled('status_request'));
        $config->disableExtension('status_request');
        $this->assertFalse($config->isExtensionEnabled('status_request'));

        // 测试禁用不存在的扩展
        $config->disableExtension('unknown_extension');
        $this->assertFalse($config->isExtensionEnabled('unknown_extension'));

        // 测试多个扩展禁用
        $config->disableExtension('supported_groups');
        $config->disableExtension('signature_algorithms');
        $this->assertFalse($config->isExtensionEnabled('supported_groups'));
        $this->assertFalse($config->isExtensionEnabled('signature_algorithms'));
    }

    /**
     * 测试启用扩展功能
     */
    public function testEnableExtension(): void
    {
        $config = new HandshakeConfig();

        // 测试启用默认禁用的扩展
        $this->assertFalse($config->isExtensionEnabled('status_request'));
        $config->enableExtension('status_request');
        $this->assertTrue($config->isExtensionEnabled('status_request'));

        // 测试启用默认启用的扩展
        $this->assertTrue($config->isExtensionEnabled('server_name'));
        $config->enableExtension('server_name');
        $this->assertTrue($config->isExtensionEnabled('server_name'));

        // 测试启用不存在的扩展
        $config->enableExtension('new_extension');
        $this->assertTrue($config->isExtensionEnabled('new_extension'));

        // 测试多个扩展启用
        $config->enableExtension('early_data');
        $config->enableExtension('pre_shared_key');
        $this->assertTrue($config->isExtensionEnabled('early_data'));
        $this->assertTrue($config->isExtensionEnabled('pre_shared_key'));

        // 测试启用后再禁用
        $config->enableExtension('test_extension');
        $this->assertTrue($config->isExtensionEnabled('test_extension'));
        $config->disableExtension('test_extension');
        $this->assertFalse($config->isExtensionEnabled('test_extension'));
    }
}
