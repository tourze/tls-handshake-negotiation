<?php

namespace Tourze\TLSHandshakeNegotiation\Tests\KeyDerivation;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshakeNegotiation\KeyDerivation\VerifyDataGenerator;

/**
 * 验证数据生成器测试
 *
 * @internal
 */
#[CoversClass(VerifyDataGenerator::class)]
final class VerifyDataGeneratorTest extends TestCase
{
    /**
     * 测试TLS 1.2客户端验证数据生成
     */
    public function testTLS12ClientVerifyData(): void
    {
        $masterSecret = random_bytes(48);
        $handshakeMessages = 'ClientHello + ServerHello + Certificate + ServerKeyExchange + ServerHelloDone + ClientKeyExchange + ChangeCipherSpec';

        $generator = new VerifyDataGenerator();
        $verifyData = $generator->generateTLS12ClientVerifyData($masterSecret, $handshakeMessages);

        $this->assertNotEmpty($verifyData);
        $this->assertSame(12, strlen($verifyData)); // TLS 1.2验证数据为12字节
    }

    /**
     * 测试TLS 1.2服务器验证数据生成
     */
    public function testTLS12ServerVerifyData(): void
    {
        $masterSecret = random_bytes(48);
        $handshakeMessages = 'ClientHello + ServerHello + Certificate + ServerKeyExchange + ServerHelloDone + ClientKeyExchange + ChangeCipherSpec + Finished';

        $generator = new VerifyDataGenerator();
        $verifyData = $generator->generateTLS12ServerVerifyData($masterSecret, $handshakeMessages);

        $this->assertNotEmpty($verifyData);
        $this->assertSame(12, strlen($verifyData)); // TLS 1.2验证数据为12字节
    }

    /**
     * 测试TLS 1.3客户端验证数据生成
     */
    public function testTLS13ClientVerifyData(): void
    {
        $baseKey = random_bytes(32);
        $handshakeContext = 'ClientHello + ServerHello + EncryptedExtensions + Certificate + CertificateVerify';

        $generator = new VerifyDataGenerator();
        $verifyData = $generator->generateTLS13ClientVerifyData($baseKey, $handshakeContext);

        $this->assertNotEmpty($verifyData);
    }

    /**
     * 测试TLS 1.3服务器验证数据生成
     */
    public function testTLS13ServerVerifyData(): void
    {
        $baseKey = random_bytes(32);
        $handshakeContext = 'ClientHello + ServerHello + EncryptedExtensions + Certificate + CertificateVerify + Finished';

        $generator = new VerifyDataGenerator();
        $verifyData = $generator->generateTLS13ServerVerifyData($baseKey, $handshakeContext);

        $this->assertNotEmpty($verifyData);
    }

    /**
     * 测试相同输入产生相同验证数据
     */
    public function testConsistency(): void
    {
        $masterSecret = random_bytes(48);
        $handshakeMessages = 'ClientHello + ServerHello + Certificate + ServerKeyExchange + ServerHelloDone + ClientKeyExchange + ChangeCipherSpec';

        $generator = new VerifyDataGenerator();
        $verify1 = $generator->generateTLS12ClientVerifyData($masterSecret, $handshakeMessages);
        $verify2 = $generator->generateTLS12ClientVerifyData($masterSecret, $handshakeMessages);

        $this->assertSame($verify1, $verify2);
    }

    /**
     * 测试不同消息产生不同验证数据
     */
    public function testDifferentMessages(): void
    {
        $masterSecret = random_bytes(48);
        $messages1 = 'ClientHello + ServerHello';
        $messages2 = 'ClientHello + ServerHello + Certificate';

        $generator = new VerifyDataGenerator();
        $verify1 = $generator->generateTLS12ClientVerifyData($masterSecret, $messages1);
        $verify2 = $generator->generateTLS12ClientVerifyData($masterSecret, $messages2);

        $this->assertNotSame($verify1, $verify2);
    }

    /**
     * 测试生成TLS 1.2客户端验证数据
     */
    public function testGenerateTLS12ClientVerifyData(): void
    {
        $masterSecret = random_bytes(48);
        $handshakeMessages = 'ClientHello + ServerHello + Certificate + ServerKeyExchange + ServerHelloDone + ClientKeyExchange + ChangeCipherSpec';

        $generator = new VerifyDataGenerator();
        $verifyData = $generator->generateTLS12ClientVerifyData($masterSecret, $handshakeMessages);

        $this->assertNotEmpty($verifyData);
        $this->assertSame(12, strlen($verifyData)); // TLS 1.2验证数据为12字节

        // 测试一致性
        $verifyData2 = $generator->generateTLS12ClientVerifyData($masterSecret, $handshakeMessages);
        $this->assertSame($verifyData, $verifyData2);
    }

    /**
     * 测试生成TLS 1.2服务器验证数据
     */
    public function testGenerateTLS12ServerVerifyData(): void
    {
        $masterSecret = random_bytes(48);
        $handshakeMessages = 'ClientHello + ServerHello + Certificate + ServerKeyExchange + ServerHelloDone + ClientKeyExchange + ChangeCipherSpec + Finished';

        $generator = new VerifyDataGenerator();
        $verifyData = $generator->generateTLS12ServerVerifyData($masterSecret, $handshakeMessages);

        $this->assertNotEmpty($verifyData);
        $this->assertSame(12, strlen($verifyData)); // TLS 1.2验证数据为12字节

        // 客户端和服务器验证数据应该不同
        $clientVerifyData = $generator->generateTLS12ClientVerifyData($masterSecret, $handshakeMessages);
        $this->assertNotSame($verifyData, $clientVerifyData);
    }

    /**
     * 测试生成TLS 1.3客户端验证数据
     */
    public function testGenerateTLS13ClientVerifyData(): void
    {
        $baseKey = random_bytes(32);
        $handshakeContext = 'ClientHello + ServerHello + EncryptedExtensions + Certificate + CertificateVerify';

        $generator = new VerifyDataGenerator();
        $verifyData = $generator->generateTLS13ClientVerifyData($baseKey, $handshakeContext);

        $this->assertNotEmpty($verifyData);
        $this->assertSame(32, strlen($verifyData)); // TLS 1.3验证数据为32字节(SHA-256)

        // 测试一致性
        $verifyData2 = $generator->generateTLS13ClientVerifyData($baseKey, $handshakeContext);
        $this->assertSame($verifyData, $verifyData2);
    }

    /**
     * 测试生成TLS 1.3服务器验证数据
     */
    public function testGenerateTLS13ServerVerifyData(): void
    {
        $baseKey = random_bytes(32);
        $handshakeContext = 'ClientHello + ServerHello + EncryptedExtensions + Certificate + CertificateVerify + Finished';

        $generator = new VerifyDataGenerator();
        $verifyData = $generator->generateTLS13ServerVerifyData($baseKey, $handshakeContext);

        $this->assertNotEmpty($verifyData);
        $this->assertSame(32, strlen($verifyData)); // TLS 1.3验证数据为32字节(SHA-256)

        // 不同基础密钥应产生不同的验证数据
        $differentBaseKey = random_bytes(32);
        $differentVerifyData = $generator->generateTLS13ServerVerifyData($differentBaseKey, $handshakeContext);
        $this->assertNotSame($verifyData, $differentVerifyData);
    }

    /**
     * 测试验证TLS 1.2客户端数据
     */
    public function testVerifyTLS12ClientData(): void
    {
        $masterSecret = random_bytes(48);
        $handshakeMessages = 'ClientHello + ServerHello + Certificate + ServerKeyExchange + ServerHelloDone + ClientKeyExchange + ChangeCipherSpec';

        $generator = new VerifyDataGenerator();
        $verifyData = $generator->generateTLS12ClientVerifyData($masterSecret, $handshakeMessages);

        // 正确的验证数据应该验证通过
        $this->assertTrue($generator->verifyTLS12ClientData($verifyData, $masterSecret, $handshakeMessages));

        // 错误的验证数据应该验证失败
        $wrongVerifyData = random_bytes(12);
        $this->assertFalse($generator->verifyTLS12ClientData($wrongVerifyData, $masterSecret, $handshakeMessages));

        // 错误的主密钥应该验证失败
        $wrongMasterSecret = random_bytes(48);
        $this->assertFalse($generator->verifyTLS12ClientData($verifyData, $wrongMasterSecret, $handshakeMessages));
    }

    /**
     * 测试验证TLS 1.2服务器数据
     */
    public function testVerifyTLS12ServerData(): void
    {
        $masterSecret = random_bytes(48);
        $handshakeMessages = 'ClientHello + ServerHello + Certificate + ServerKeyExchange + ServerHelloDone + ClientKeyExchange + ChangeCipherSpec + Finished';

        $generator = new VerifyDataGenerator();
        $verifyData = $generator->generateTLS12ServerVerifyData($masterSecret, $handshakeMessages);

        // 正确的验证数据应该验证通过
        $this->assertTrue($generator->verifyTLS12ServerData($verifyData, $masterSecret, $handshakeMessages));

        // 错误的验证数据应该验证失败
        $wrongVerifyData = random_bytes(12);
        $this->assertFalse($generator->verifyTLS12ServerData($wrongVerifyData, $masterSecret, $handshakeMessages));

        // 错误的握手消息应该验证失败
        $wrongMessages = 'ClientHello + ServerHello';
        $this->assertFalse($generator->verifyTLS12ServerData($verifyData, $masterSecret, $wrongMessages));
    }

    /**
     * 测试验证TLS 1.3客户端数据
     */
    public function testVerifyTLS13ClientData(): void
    {
        $baseKey = random_bytes(32);
        $handshakeContext = 'ClientHello + ServerHello + EncryptedExtensions + Certificate + CertificateVerify';

        $generator = new VerifyDataGenerator();
        $verifyData = $generator->generateTLS13ClientVerifyData($baseKey, $handshakeContext);

        // 正确的验证数据应该验证通过
        $this->assertTrue($generator->verifyTLS13ClientData($verifyData, $baseKey, $handshakeContext));

        // 错误的验证数据应该验证失败
        $wrongVerifyData = random_bytes(32);
        $this->assertFalse($generator->verifyTLS13ClientData($wrongVerifyData, $baseKey, $handshakeContext));

        // 错误的基础密钥应该验证失败
        $wrongBaseKey = random_bytes(32);
        $this->assertFalse($generator->verifyTLS13ClientData($verifyData, $wrongBaseKey, $handshakeContext));
    }

    /**
     * 测试验证TLS 1.3服务器数据
     */
    public function testVerifyTLS13ServerData(): void
    {
        $baseKey = random_bytes(32);
        $handshakeContext = 'ClientHello + ServerHello + EncryptedExtensions + Certificate + CertificateVerify + Finished';

        $generator = new VerifyDataGenerator();
        $verifyData = $generator->generateTLS13ServerVerifyData($baseKey, $handshakeContext);

        // 正确的验证数据应该验证通过
        $this->assertTrue($generator->verifyTLS13ServerData($verifyData, $baseKey, $handshakeContext));

        // 错误的验证数据应该验证失败
        $wrongVerifyData = random_bytes(32);
        $this->assertFalse($generator->verifyTLS13ServerData($wrongVerifyData, $baseKey, $handshakeContext));

        // 错误的握手上下文应该验证失败
        $wrongContext = 'ClientHello + ServerHello';
        $this->assertFalse($generator->verifyTLS13ServerData($verifyData, $baseKey, $wrongContext));
    }
}
