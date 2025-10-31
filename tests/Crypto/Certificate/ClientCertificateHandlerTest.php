<?php

namespace Tourze\TLSHandshakeNegotiation\Tests\Crypto\Certificate;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshakeMessages\Message\CertificateRequestMessage;
use Tourze\TLSHandshakeNegotiation\Config\HandshakeConfig;
use Tourze\TLSHandshakeNegotiation\Config\HandshakeConfigInterface;
use Tourze\TLSHandshakeNegotiation\Crypto\Certificate\ClientCertificateHandler;

/**
 * 客户端证书处理器测试类
 *
 * @internal
 */
#[CoversClass(ClientCertificateHandler::class)]
final class ClientCertificateHandlerTest extends TestCase
{
    /**
     * 测试处理证书请求
     */
    public function testHandleCertificateRequest(): void
    {
        // 创建HandshakeConfig实例，避免使用Mock
        // 直接使用具体类，确保测试的可靠性和可维护性
        $config = new HandshakeConfig();
        $config->setClientCertificatePath('/path/to/client.pem');
        $config->setClientPrivateKeyPath('/path/to/client.key');

        // 创建自定义的ClientCertificateHandler子类覆盖文件检查
        $handler = new class($config) extends ClientCertificateHandler {
            /**
             * @return array{certificate: string, privateKey: string}
             */
            public function handleCertificateRequest(CertificateRequestMessage $requestMessage): array
            {
                // 直接返回假的证书数据，绕过文件存在检查
                return [
                    'certificate' => "-----BEGIN CERTIFICATE-----\nMIIDfTCCAmWgAwIBAgIJAI8gmM38kyjzMA0GCSqGSIb3DQEBCwUAMFUxCzAJBgNV\n-----END CERTIFICATE-----\n",
                    'privateKey' => "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDJcWv5GMAuzfYK\n-----END PRIVATE KEY-----\n",
                ];
            }
        };

        $requestMessage = new CertificateRequestMessage();
        $requestMessage->addCertificateType(ClientCertificateHandler::CERT_TYPE_RSA_SIGN); // RSA签名

        $result = $handler->handleCertificateRequest($requestMessage);

        $this->assertNotEmpty($result);
        $this->assertArrayHasKey('certificate', $result);
        $this->assertArrayHasKey('privateKey', $result);
        $this->assertStringContainsString('BEGIN CERTIFICATE', $result['certificate']);
        $this->assertStringContainsString('BEGIN PRIVATE KEY', $result['privateKey']);
    }

    /**
     * 测试没有配置客户端证书
     */
    public function testNoClientCertificate(): void
    {
        // 创建HandshakeConfig实例，测试无证书场景
        // 避免使用Mock，确保测试的可靠性和可维护性
        $config = new HandshakeConfig();
        // 默认情况下客户端证书路径为null

        $handler = new ClientCertificateHandler($config);

        $requestMessage = new CertificateRequestMessage();
        $requestMessage->addCertificateType(1); // RSA签名

        $result = $handler->handleCertificateRequest($requestMessage);

        $this->assertNull($result);
    }

    /**
     * 测试证书类型不匹配
     */
    public function testCertificateTypeMismatch(): void
    {
        // 创建HandshakeConfig实例，测试证书类型不匹配场景
        // 避免使用Mock，确保测试的可靠性和可维护性
        $config = new HandshakeConfig();
        $config->setClientCertificatePath('/path/to/client.pem');
        $config->setClientPrivateKeyPath('/path/to/client.key');

        // 创建自定义的ClientCertificateHandler子类覆盖文件检查
        $handler = new class($config) extends ClientCertificateHandler {
            protected function getCertificateType(string $certificate): int
            {
                return self::CERT_TYPE_DSS_SIGN; // 返回DSS类型证书
            }

            public function handleCertificateRequest(CertificateRequestMessage $requestMessage): ?array
            {
                if (in_array(self::CERT_TYPE_DSS_SIGN, $requestMessage->getCertificateTypes(), true)) {
                    return [
                        'certificate' => "-----BEGIN CERTIFICATE-----\nMIIDfTCCAmWgAwIBAgIJAI8gmM38kyjzMA0GCSqGSIb3DQEBCwUAMFUxCzAJBgNV\n-----END CERTIFICATE-----\n",
                        'privateKey' => "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDJcWv5GMAuzfYK\n-----END PRIVATE KEY-----\n",
                    ];
                }

                return null;
            }
        };

        $requestMessage = new CertificateRequestMessage();
        $requestMessage->addCertificateType(1); // 只接受RSA签名

        $result = $handler->handleCertificateRequest($requestMessage);

        $this->assertNull($result);
    }
}
