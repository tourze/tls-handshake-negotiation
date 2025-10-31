<?php

namespace Tourze\TLSHandshakeNegotiation\Tests\KeyDerivation;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshakeNegotiation\KeyDerivation\MasterSecretDeriver;

/**
 * 主密钥派生器测试
 *
 * @internal
 */
#[CoversClass(MasterSecretDeriver::class)]
final class MasterSecretDeriverTest extends TestCase
{
    /**
     * 测试TLS 1.2主密钥派生
     */
    public function testTLS12MasterSecretDerivation(): void
    {
        $premaster = random_bytes(48);
        $clientRandom = random_bytes(32);
        $serverRandom = random_bytes(32);

        $deriver = new MasterSecretDeriver();
        $master = $deriver->deriveTLS12($premaster, $clientRandom, $serverRandom);

        $this->assertNotEmpty($master);
        $this->assertSame(48, strlen($master));
    }

    /**
     * 测试TLS 1.3主密钥派生
     */
    public function testTLS13MasterSecretDerivation(): void
    {
        $handshakeSecret = random_bytes(32);

        $deriver = new MasterSecretDeriver();
        $master = $deriver->deriveTLS13($handshakeSecret);

        $this->assertNotEmpty($master);
        $this->assertSame(32, strlen($master)); // SHA-256哈希输出长度
    }

    /**
     * 测试deriveTLS12方法
     */
    public function testDeriveTLS12(): void
    {
        $premaster = random_bytes(48);
        $clientRandom = random_bytes(32);
        $serverRandom = random_bytes(32);

        $deriver = new MasterSecretDeriver();
        $master = $deriver->deriveTLS12($premaster, $clientRandom, $serverRandom);

        $this->assertNotEmpty($master);
        $this->assertSame(48, strlen($master));

        // 测试一致性
        $master2 = $deriver->deriveTLS12($premaster, $clientRandom, $serverRandom);
        $this->assertSame($master, $master2);
    }

    /**
     * 测试deriveTLS13方法
     */
    public function testDeriveTLS13(): void
    {
        $handshakeSecret = random_bytes(32);

        $deriver = new MasterSecretDeriver();
        $master = $deriver->deriveTLS13($handshakeSecret);

        $this->assertNotEmpty($master);
        $this->assertSame(32, strlen($master));

        // 测试一致性
        $master2 = $deriver->deriveTLS13($handshakeSecret);
        $this->assertSame($master, $master2);
    }

    /**
     * 测试TLS 1.2相同输入产生相同密钥
     */
    public function testTLS12Consistency(): void
    {
        $premaster = random_bytes(48);
        $clientRandom = random_bytes(32);
        $serverRandom = random_bytes(32);

        $deriver = new MasterSecretDeriver();
        $master1 = $deriver->deriveTLS12($premaster, $clientRandom, $serverRandom);
        $master2 = $deriver->deriveTLS12($premaster, $clientRandom, $serverRandom);

        $this->assertSame($master1, $master2);
    }

    /**
     * 测试TLS 1.3相同输入产生相同密钥
     */
    public function testTLS13Consistency(): void
    {
        $handshakeSecret = random_bytes(32);

        $deriver = new MasterSecretDeriver();
        $master1 = $deriver->deriveTLS13($handshakeSecret);
        $master2 = $deriver->deriveTLS13($handshakeSecret);

        $this->assertSame($master1, $master2);
    }

    /**
     * 测试TLS 1.2密钥导出向量
     * 注意：这是一个假设的测试向量，实际实现中应替换为真实测试数据
     */
    public function testTLS12Vectors(): void
    {
        $premaster = hex2bin('0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f');
        $clientRandom = hex2bin('4041424344454647484a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f');
        $serverRandom = hex2bin('707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f');

        $this->assertNotFalse($premaster);
        $this->assertNotFalse($clientRandom);
        $this->assertNotFalse($serverRandom);

        $deriver = new MasterSecretDeriver();
        $master = $deriver->deriveTLS12($premaster, $clientRandom, $serverRandom);

        $this->assertSame(48, strlen($master));
    }

    /**
     * 测试创建TLS 1.3早期密钥
     */
    public function testCreateTLS13EarlySecret(): void
    {
        $deriver = new MasterSecretDeriver();

        // 测试无PSK的早期密钥
        $earlySecret = $deriver->createTLS13EarlySecret();
        $this->assertNotEmpty($earlySecret);
        $this->assertSame(32, strlen($earlySecret)); // SHA-256哈希输出长度

        // 测试有PSK的早期密钥
        $psk = random_bytes(32);
        $earlySecretWithPsk = $deriver->createTLS13EarlySecret($psk);
        $this->assertNotEmpty($earlySecretWithPsk);
        $this->assertSame(32, strlen($earlySecretWithPsk));

        // 不同PSK应产生不同的早期密钥
        $this->assertNotSame($earlySecret, $earlySecretWithPsk);
    }

    /**
     * 测试派生客户端应用流量密钥
     */
    public function testDeriveClientApplicationTrafficSecret(): void
    {
        $masterSecret = random_bytes(32);
        $handshakeContext = 'ClientHello + ServerHello + Certificate + CertificateVerify + Finished';

        $deriver = new MasterSecretDeriver();
        $clientSecret = $deriver->deriveClientApplicationTrafficSecret($masterSecret, $handshakeContext);

        $this->assertNotEmpty($clientSecret);
        $this->assertSame(32, strlen($clientSecret));

        // 相同输入应产生相同结果
        $clientSecret2 = $deriver->deriveClientApplicationTrafficSecret($masterSecret, $handshakeContext);
        $this->assertSame($clientSecret, $clientSecret2);
    }

    /**
     * 测试派生客户端握手流量密钥
     */
    public function testDeriveClientHandshakeTrafficSecret(): void
    {
        $handshakeSecret = random_bytes(32);
        $handshakeContext = 'ClientHello + ServerHello';

        $deriver = new MasterSecretDeriver();
        $clientTrafficSecret = $deriver->deriveClientHandshakeTrafficSecret($handshakeSecret, $handshakeContext);

        $this->assertNotEmpty($clientTrafficSecret);
        $this->assertSame(32, strlen($clientTrafficSecret));

        // 不同上下文应产生不同的密钥
        $differentContext = 'ClientHello + ServerHello + Certificate';
        $differentSecret = $deriver->deriveClientHandshakeTrafficSecret($handshakeSecret, $differentContext);
        $this->assertNotSame($clientTrafficSecret, $differentSecret);
    }

    /**
     * 测试派生导出主密钥
     */
    public function testDeriveExporterMasterSecret(): void
    {
        $masterSecret = random_bytes(32);
        $handshakeContext = 'ClientHello + ServerHello + Certificate + CertificateVerify + Finished';

        $deriver = new MasterSecretDeriver();
        $exporterSecret = $deriver->deriveExporterMasterSecret($masterSecret, $handshakeContext);

        $this->assertNotEmpty($exporterSecret);
        $this->assertSame(32, strlen($exporterSecret));

        // 相同输入应产生相同结果
        $exporterSecret2 = $deriver->deriveExporterMasterSecret($masterSecret, $handshakeContext);
        $this->assertSame($exporterSecret, $exporterSecret2);
    }

    /**
     * 测试派生握手密钥
     */
    public function testDeriveHandshakeSecret(): void
    {
        $earlySecret = random_bytes(32);
        $sharedSecret = random_bytes(32);

        $deriver = new MasterSecretDeriver();
        $handshakeSecret = $deriver->deriveHandshakeSecret($earlySecret, $sharedSecret);

        $this->assertNotEmpty($handshakeSecret);
        $this->assertSame(32, strlen($handshakeSecret));

        // 不同的共享密钥应产生不同的握手密钥
        $differentSharedSecret = random_bytes(32);
        $differentHandshakeSecret = $deriver->deriveHandshakeSecret($earlySecret, $differentSharedSecret);
        $this->assertNotSame($handshakeSecret, $differentHandshakeSecret);
    }

    /**
     * 测试派生恢复主密钥
     */
    public function testDeriveResumptionMasterSecret(): void
    {
        $masterSecret = random_bytes(32);
        $handshakeContext = 'ClientHello + ServerHello + Certificate + CertificateVerify + Finished';

        $deriver = new MasterSecretDeriver();
        $resumptionSecret = $deriver->deriveResumptionMasterSecret($masterSecret, $handshakeContext);

        $this->assertNotEmpty($resumptionSecret);
        $this->assertSame(32, strlen($resumptionSecret));

        // 相同输入应产生相同结果
        $resumptionSecret2 = $deriver->deriveResumptionMasterSecret($masterSecret, $handshakeContext);
        $this->assertSame($resumptionSecret, $resumptionSecret2);
    }

    /**
     * 测试派生服务器应用流量密钥
     */
    public function testDeriveServerApplicationTrafficSecret(): void
    {
        $masterSecret = random_bytes(32);
        $handshakeContext = 'ClientHello + ServerHello + Certificate + CertificateVerify + Finished';

        $deriver = new MasterSecretDeriver();
        $serverSecret = $deriver->deriveServerApplicationTrafficSecret($masterSecret, $handshakeContext);

        $this->assertNotEmpty($serverSecret);
        $this->assertSame(32, strlen($serverSecret));

        // 服务器和客户端应用流量密钥应该不同
        $clientSecret = $deriver->deriveClientApplicationTrafficSecret($masterSecret, $handshakeContext);
        $this->assertNotSame($serverSecret, $clientSecret);
    }

    /**
     * 测试派生服务器握手流量密钥
     */
    public function testDeriveServerHandshakeTrafficSecret(): void
    {
        $handshakeSecret = random_bytes(32);
        $handshakeContext = 'ClientHello + ServerHello';

        $deriver = new MasterSecretDeriver();
        $serverTrafficSecret = $deriver->deriveServerHandshakeTrafficSecret($handshakeSecret, $handshakeContext);

        $this->assertNotEmpty($serverTrafficSecret);
        $this->assertSame(32, strlen($serverTrafficSecret));

        // 服务器和客户端握手流量密钥应该不同
        $clientTrafficSecret = $deriver->deriveClientHandshakeTrafficSecret($handshakeSecret, $handshakeContext);
        $this->assertNotSame($serverTrafficSecret, $clientTrafficSecret);
    }
}
