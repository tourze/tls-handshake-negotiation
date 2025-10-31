<?php

namespace Tourze\TLSHandshakeNegotiation\Crypto\Certificate;

use Tourze\TLSHandshakeNegotiation\Config\HandshakeConfig;
use Tourze\TLSHandshakeNegotiation\Exception\CertificateException;

/**
 * 服务器证书选择器
 */
class ServerCertificateSelector
{
    /**
     * 构造函数
     *
     * @param HandshakeConfig $config 握手配置
     */
    public function __construct(private readonly HandshakeConfig $config)
    {
    }

    /**
     * 根据客户端支持的签名算法选择合适的证书
     *
     * @param array<int> $clientSupportedSignatureAlgorithms 客户端支持的签名算法列表
     *
     * @return array{certificate: string, privateKey: string} 选择的证书及私钥
     *
     * @throws CertificateException 如果没有匹配的证书
     */
    public function selectCertificate(array $clientSupportedSignatureAlgorithms): array
    {
        $certData = $this->loadCertificateFromConfig();

        // 如果客户端没有指定签名算法，直接返回服务器证书
        if ([] === $clientSupportedSignatureAlgorithms) {
            return $certData;
        }

        if ($this->isSignatureAlgorithmSupported($certData['certificate'], $clientSupportedSignatureAlgorithms)) {
            return $certData;
        }

        throw new CertificateException('没有找到匹配的证书');
    }

    /**
     * 从配置加载证书数据
     *
     * @return array{certificate: string, privateKey: string} 证书及私钥数据
     *
     * @throws CertificateException 如果证书文件不存在或加载失败
     */
    private function loadCertificateFromConfig(): array
    {
        $certPath = $this->config->getCertificatePath();
        $keyPath = $this->config->getPrivateKeyPath();

        if (null === $certPath || null === $keyPath || !file_exists($certPath) || !file_exists($keyPath)) {
            throw new CertificateException('证书文件不存在');
        }

        return $this->loadCertificateData($certPath, $keyPath);
    }

    /**
     * 检查证书的签名算法是否被客户端支持
     *
     * @param string     $certificate                        证书数据
     * @param array<int> $clientSupportedSignatureAlgorithms 客户端支持的签名算法列表
     *
     * @return bool 是否支持
     */
    private function isSignatureAlgorithmSupported(string $certificate, array $clientSupportedSignatureAlgorithms): bool
    {
        // 获取服务器证书使用的签名算法
        $certSignatureAlgorithm = $this->getCertificateSignatureAlgorithm($certificate);

        // 检查客户端是否支持服务器证书的签名算法
        if (in_array($certSignatureAlgorithm, $clientSupportedSignatureAlgorithms, true)) {
            return true;
        }

        // 处理特殊情况：RSA证书但需要PSS签名等
        return $this->isRSACertificateWithPSSSupport($certificate, $clientSupportedSignatureAlgorithms);
    }

    /**
     * 检查RSA证书是否支持PSS签名
     *
     * @param string     $certificate                        证书数据
     * @param array<int> $clientSupportedSignatureAlgorithms 客户端支持的签名算法列表
     *
     * @return bool 是否支持
     */
    private function isRSACertificateWithPSSSupport(string $certificate, array $clientSupportedSignatureAlgorithms): bool
    {
        if (!$this->isRSACertificate($certificate)) {
            return false;
        }

        // TLS 1.3中RSA证书可以用于PSS签名
        foreach ($clientSupportedSignatureAlgorithms as $algorithm) {
            // 0x0804, 0x0805, 0x0806是TLS 1.3中的RSA-PSS算法
            if (in_array($algorithm, [0x0804, 0x0805, 0x0806], true)) {
                return true;
            }
        }

        return false;
    }

    /**
     * 加载证书和私钥数据
     *
     * @param string $certPath 证书路径
     * @param string $keyPath  私钥路径
     *
     * @return array{certificate: string, privateKey: string} 证书及私钥数据
     *
     * @throws CertificateException 如果加载失败
     */
    protected function loadCertificateData(string $certPath, string $keyPath): array
    {
        $certificate = file_get_contents($certPath);
        $privateKey = file_get_contents($keyPath);

        if (false === $certificate || false === $privateKey) {
            throw new CertificateException('无法读取证书或私钥文件');
        }

        // 验证证书和私钥格式
        if (false === openssl_x509_read($certificate)) {
            throw new CertificateException('无效的证书格式');
        }

        if (false === openssl_pkey_get_private($privateKey)) {
            throw new CertificateException('无效的私钥格式');
        }

        // 检查证书和私钥是否匹配
        if (!$this->certificateKeyPairMatch($certificate, $privateKey)) {
            throw new CertificateException('证书与私钥不匹配');
        }

        return [
            'certificate' => $certificate,
            'privateKey' => $privateKey,
        ];
    }

    /**
     * 获取证书的签名算法
     *
     * @param string $certificate 证书数据
     *
     * @return int 签名算法标识符
     */
    protected function getCertificateSignatureAlgorithm(string $certificate): int
    {
        $certInfo = openssl_x509_parse($certificate);
        if (false === $certInfo || !isset($certInfo['signatureTypeSN'])) {
            // 默认返回RSA-SHA256
            return 0x0401;
        }

        // 根据签名类型映射到TLS中的签名算法标识符
        return match ($certInfo['signatureTypeSN']) {
            'RSA-SHA256' => 0x0401,
            'RSA-SHA384' => 0x0501,
            'RSA-SHA512' => 0x0601,
            'DSA-SHA256' => 0x0402,
            'ECDSA-SHA256' => 0x0403,
            'ECDSA-SHA384' => 0x0503,
            'ECDSA-SHA512' => 0x0603,
            default => 0x0401, // 默认使用RSA-SHA256
        };
    }

    /**
     * 判断证书是否为RSA类型
     *
     * @param string $certificate 证书数据
     *
     * @return bool 是否为RSA证书
     */
    protected function isRSACertificate(string $certificate): bool
    {
        $certResource = openssl_x509_read($certificate);
        if (false === $certResource) {
            return false;
        }

        $publicKey = openssl_get_publickey($certResource);
        if (false === $publicKey) {
            return false;
        }

        $keyDetails = openssl_pkey_get_details($publicKey);

        return isset($keyDetails['type']) && OPENSSL_KEYTYPE_RSA === $keyDetails['type'];
    }

    /**
     * 验证证书和私钥是否匹配
     *
     * @param string $certificate 证书数据
     * @param string $privateKey  私钥数据
     *
     * @return bool 是否匹配
     */
    protected function certificateKeyPairMatch(string $certificate, string $privateKey): bool
    {
        $cert = openssl_x509_read($certificate);
        $key = openssl_pkey_get_private($privateKey);

        if (false === $cert || false === $key) {
            return false;
        }

        $certDetails = openssl_x509_parse($cert);
        $keyDetails = openssl_pkey_get_details($key);

        if (false === $certDetails || false === $keyDetails || !isset($certDetails['key']) || !isset($keyDetails['key'])) {
            return false;
        }

        // 比较公钥模数
        return $certDetails['key'] === $keyDetails['key'];
    }
}
