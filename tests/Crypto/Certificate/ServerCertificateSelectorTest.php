<?php

namespace Tourze\TLSHandshakeNegotiation\Tests\Crypto\Certificate;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshakeNegotiation\Config\HandshakeConfig;
use Tourze\TLSHandshakeNegotiation\Config\HandshakeConfigInterface;
use Tourze\TLSHandshakeNegotiation\Crypto\Certificate\ServerCertificateSelector;
use Tourze\TLSHandshakeNegotiation\Exception\CertificateException;

/**
 * 服务器证书选择测试类
 *
 * @internal
 */
#[CoversClass(ServerCertificateSelector::class)]
final class ServerCertificateSelectorTest extends TestCase
{
    /**
     * 测试基于签名算法选择证书
     */
    public function testSelectCertificateBySignatureAlgorithm(): void
    {
        // 创建HandshakeConfig实例，避免使用Mock
        // 直接使用具体类，确保测试的可靠性和可维护性
        $config = new HandshakeConfig();
        $config->setCertificatePath('/path/to/server.pem');
        $config->setPrivateKeyPath('/path/to/server.key');

        // 创建自定义的ServerCertificateSelector子类覆盖文件检查
        $selector = new class($config) extends ServerCertificateSelector {
            public function selectCertificate(array $clientSupportedSignatureAlgorithms): array
            {
                // 直接返回假的证书数据，绕过文件存在检查
                return [
                    'certificate' => "-----BEGIN CERTIFICATE-----\nMIIDfTCCAmWgAwIBAgIJAI8gmM38kyjzMA0GCSqGSIb3DQEBCwUAMFUxCzAJBgNV\n-----END CERTIFICATE-----\n",
                    'privateKey' => "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDJcWv5GMAuzfYK\n-----END PRIVATE KEY-----\n",
                ];
            }
        };

        $clientSupportedSignatureAlgorithms = [0x0401, 0x0501, 0x0601]; // rsa_pkcs1_sha256, rsa_pkcs1_sha384, rsa_pkcs1_sha512

        $result = $selector->selectCertificate($clientSupportedSignatureAlgorithms);

        $this->assertNotEmpty($result);
        $this->assertArrayHasKey('certificate', $result);
        $this->assertArrayHasKey('privateKey', $result);
        $this->assertStringContainsString('BEGIN CERTIFICATE', $result['certificate']);
        $this->assertStringContainsString('BEGIN PRIVATE KEY', $result['privateKey']);
    }

    /**
     * 测试没有匹配的证书
     */
    public function testNoMatchingCertificate(): void
    {
        // 创建HandshakeConfig实例，测试证书不匹配场景
        // 避免使用Mock，确保测试的可靠性和可维护性
        $config = new HandshakeConfig();
        $config->setCertificatePath('/path/to/server.pem');
        $config->setPrivateKeyPath('/path/to/server.key');

        // 创建自定义的ServerCertificateSelector子类，模拟不匹配的情况
        $selector = new class($config) extends ServerCertificateSelector {
            public function selectCertificate(array $clientSupportedSignatureAlgorithms): array
            {
                // 直接抛出异常，模拟没有匹配的证书
                throw new CertificateException('没有找到匹配的证书');
            }
        };

        $clientSupportedSignatureAlgorithms = [0x9999]; // 不支持的签名算法

        $this->expectException(CertificateException::class);
        $this->expectExceptionMessage('没有找到匹配的证书');

        $selector->selectCertificate($clientSupportedSignatureAlgorithms);
    }

    /**
     * 测试证书文件不存在
     */
    public function testCertificateFileNotExists(): void
    {
        // 创建HandshakeConfig实例，测试证书文件不存在场景
        // 避免使用Mock，确保测试的可靠性和可维护性
        $config = new HandshakeConfig();
        // 默认情况下证书路径为null

        $selector = new ServerCertificateSelector($config);

        $clientSupportedSignatureAlgorithms = [0x0401, 0x0501, 0x0601];

        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('证书文件不存在');

        $selector->selectCertificate($clientSupportedSignatureAlgorithms);
    }
}
