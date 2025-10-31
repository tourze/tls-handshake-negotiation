<?php

namespace Tourze\TLSHandshakeNegotiation\Tests\Crypto\Certificate;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshakeMessages\Message\CertificateVerifyMessage;
use Tourze\TLSHandshakeNegotiation\Crypto\Certificate\CertificateVerifyGenerator;

/**
 * 证书验证消息生成器测试类
 *
 * @internal
 */
#[CoversClass(CertificateVerifyGenerator::class)]
final class CertificateVerifyGeneratorTest extends TestCase
{
    private CertificateVerifyGenerator $generator;

    /**
     * 有效的RSA私钥（用于测试）
     */
    private const TEST_PRIVATE_KEY = '-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCODDUIYOAuk/O6
to/Aaf5Jx3oI+PWcDrqg9Jl4usFm3ny1B/6ZYZLyA2Jwnhbt4XVzn+jXI0Necn12
FC+5jP+en5wk4XbLPqH6Ce4WStFhYqELyxCzdu09N+mFyOD+sGiFjWaWEBYfkjaR
FODgST90OclLi/xyAN1Tuv5m5E61RJ2+k6EgL02asfZkCP1XOjw6kJgH66vBU/qa
o8Kmj4wUeEwcAFnXvLAQoYiPrMklFbqomoXz/cvbwxBwlQ/lgXGJ6SI8zkRrvolD
le6Aio9evtAzK5+bJY8Ui/D53QXeEWFzCPpBA3BrVdsvs12ieTCpzwz9ulcXS7KU
Kv+1Q9Z7AgMBAAECggEAFPkPxM/rlGpQkeCDSF6d/ANm16JNPqByGnJi9+S4dNl5
bOU5ndM+oLBdPXwqAy9xvwOnm57fmIyrojPdeWEBxkg8rrlXZ9o0jOLLHiF9LrV4
SnHODSFhv9Mx4zNDUnd2HJnsa/sDY9/xDJTE6yNa1MH0yvcSlpEyxzppy4P+wbFK
hpClPXH69KWBwsk/K3LWlc02ZyhTgNlC2anCw6e8luyxZDvyrDcrM/DiKoct+fgs
y0+EP7Ru1kESp3bFX40f6TkOUQ6UjdCZqSh/9rV1MwGuKZrvChehQKHwMSw/0Txr
9NQ1O7dYW7KAWo+EtWXA9MXeNsaobiN85wW+xn7oIQKBgQDFvYHei6kzaVAG1UAP
oGoNY7fOsefy07FiwpoUua1YJ8Y+oZSLCv5dHEmNDDSL67uZe3mLpLDYgMG7g5ui
oLsWjmNfxD2YG7dhSShehCzARG/Mwf05RCKzZbYFIYSpvEveDKzj1v+rXd7LgeVz
uCo17DK+aOkith7j6SDOdv9QsQKBgQC35hsatCajKsPbfwIFvpdWF6BC9qWQhl1h
8hKBJnc5hk+b9MXFQOiQTcE/0BY5DH7tgMsGKkdsrv0cJ2VvQM+TkDdzzfgDTJ6t
LKoMEbSdU4Bk4cbXcJyqfCPrSV0WRkHck9Ds/o91AObtC8WOI/0Yvu3hgusimPb3
tv1gDkIE6wKBgQCvxAmCVcYqqru1tyxgN4jNKgwiMEUqtT0BulTXg0wwBfrThTDS
fw0mmpROScETdpCklvqtQ9DmQVzzXsKixhhGrn5qi7bsVAam9S5rBTX6GVr/OJfr
pULrD8fBu89+SJ9vWvj69QsBukjlwCrCt7rdf3yDgCFq91Nx5rGAlInRoQKBgAYM
B/oh0F9vKY+PJpbfxIQtNLTe/WS6NlnhJuCeTi9TDk0XiGVLFBqio+cgRYrMsWPH
52UlgMG/I02IshotbGXyyRACxtP88f7JyDGrZ2AA/ejTT8GHz27/tAKpn+j6mHHT
XnxchoUXaYCD8ZQR9OGabaILtwWlOAG/P6en8F3PAoGBAKzsn1m1C5Wfg9ZfBseQ
PqHOnN6E6VO6fFVyv8/2mVKDpMoQUhq+JgLaCM6URy4Ff9aIVVcI3cXYR3lHFVe5
h8XENBCK0AFfLJqZ1qqLz3zRKVzVAkIjVF7iGLggtgvlvbgB/lv04gvP3C/QDVeX
p0vOvKbK+bTtVju0NaIncsmj
-----END PRIVATE KEY-----';

    /**
     * 对应的公钥（用于测试）
     */
    private const TEST_PUBLIC_KEY = '-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAjgw1CGDgLpPzuraPwGn+
Scd6CPj1nA66oPSZeLrBZt58tQf+mWGS8gNicJ4W7eF1c5/o1yNDXnJ9dhQvuYz/
np+cJOF2yz6h+gnuFkrRYWKhC8sQs3btPTfphcjg/rBohY1mlhAWH5I2kRTg4Ek/
dDnJS4v8cgDdU7r+ZuROtUSdvpOhIC9NmrH2ZAj9Vzo8OpCYB+urwVP6mqPCpo+M
FHhMHABZ17ywEKGIj6zJJRW6qJqF8/3L28MQcJUP5YFxiekiPM5Ea76JQ5XugIqP
Xr7QMyufmyWPFIvw+d0F3hFhcwj6QQNwa1XbL7Ndonkwqc8M/bpXF0uylCr/tUPW
ewIDAQAB
-----END PUBLIC KEY-----';

    protected function setUp(): void
    {
        parent::setUp();

        $this->generator = new CertificateVerifyGenerator();
    }

    /**
     * 测试TLS 1.2生成证书验证消息
     */
    public function testGenerateTLS12VerifyMessage(): void
    {
        $handshakeMessages = 'ClientHello + ServerHello + Certificate + ServerKeyExchange + ServerHelloDone + ClientKeyExchange';
        $signatureAlgorithm = 0x0401; // rsa_pkcs1_sha256

        $message = $this->generator->generateTLS12VerifyMessage($handshakeMessages, self::TEST_PRIVATE_KEY, $signatureAlgorithm);

        $this->assertInstanceOf(CertificateVerifyMessage::class, $message);
        $this->assertEquals($signatureAlgorithm, $message->getSignatureAlgorithm());
        $this->assertNotEmpty($message->getSignature());

        // 验证生成的签名可以被对应的公钥验证
        $isValid = $this->generator->verifyTLS12VerifyMessage($message, $handshakeMessages, self::TEST_PUBLIC_KEY);
        $this->assertTrue($isValid);
    }

    /**
     * 测试TLS 1.3生成证书验证消息
     */
    public function testGenerateTLS13VerifyMessage(): void
    {
        $handshakeContext = 'ClientHello + ServerHello + EncryptedExtensions + Certificate';
        $signatureAlgorithm = 0x0804; // rsa_pss_rsae_sha256

        $message = $this->generator->generateTLS13VerifyMessage($handshakeContext, self::TEST_PRIVATE_KEY, $signatureAlgorithm, 'client');

        $this->assertInstanceOf(CertificateVerifyMessage::class, $message);
        $this->assertEquals($signatureAlgorithm, $message->getSignatureAlgorithm());
        $this->assertNotEmpty($message->getSignature());

        // 验证生成的签名可以被对应的公钥验证
        $isValid = $this->generator->verifyTLS13VerifyMessage($message, $handshakeContext, self::TEST_PUBLIC_KEY, 'client');
        $this->assertTrue($isValid);
    }

    /**
     * 测试验证TLS 1.2证书验证消息
     */
    public function testVerifyTLS12VerifyMessage(): void
    {
        $handshakeMessages = 'ClientHello + ServerHello + Certificate + ServerKeyExchange + ServerHelloDone + ClientKeyExchange';

        // 首先生成一个有效的消息
        $message = $this->generator->generateTLS12VerifyMessage($handshakeMessages, self::TEST_PRIVATE_KEY, 0x0401);

        // 验证消息
        $result = $this->generator->verifyTLS12VerifyMessage($message, $handshakeMessages, self::TEST_PUBLIC_KEY);
        $this->assertTrue($result);

        // 测试无效签名
        $invalidMessage = new CertificateVerifyMessage();
        $invalidMessage->setSignatureAlgorithm(0x0401);
        $invalidMessage->setSignature(str_repeat('X', 128));

        $result = $this->generator->verifyTLS12VerifyMessage($invalidMessage, $handshakeMessages, self::TEST_PUBLIC_KEY);
        $this->assertFalse($result);
    }

    /**
     * 测试验证TLS 1.3证书验证消息
     */
    public function testVerifyTLS13VerifyMessage(): void
    {
        $handshakeContext = 'ClientHello + ServerHello + EncryptedExtensions + Certificate';

        // 首先生成一个有效的服务器消息
        $message = $this->generator->generateTLS13VerifyMessage($handshakeContext, self::TEST_PRIVATE_KEY, 0x0804, 'server');

        // 验证消息
        $result = $this->generator->verifyTLS13VerifyMessage($message, $handshakeContext, self::TEST_PUBLIC_KEY, 'server');
        $this->assertTrue($result);

        // 测试无效签名
        $invalidMessage = new CertificateVerifyMessage();
        $invalidMessage->setSignatureAlgorithm(0x0804);
        $invalidMessage->setSignature(str_repeat('Y', 256));

        $result = $this->generator->verifyTLS13VerifyMessage($invalidMessage, $handshakeContext, self::TEST_PUBLIC_KEY, 'server');
        $this->assertFalse($result);
    }

    /**
     * 测试不同的签名算法
     */
    public function testDifferentSignatureAlgorithms(): void
    {
        $handshakeMessages = 'Test handshake messages';

        // 测试SHA384算法
        $message384 = $this->generator->generateTLS12VerifyMessage($handshakeMessages, self::TEST_PRIVATE_KEY, 0x0501);
        $this->assertEquals(0x0501, $message384->getSignatureAlgorithm());
        $this->assertNotEmpty($message384->getSignature());

        // 测试SHA512算法
        $message512 = $this->generator->generateTLS12VerifyMessage($handshakeMessages, self::TEST_PRIVATE_KEY, 0x0601);
        $this->assertEquals(0x0601, $message512->getSignatureAlgorithm());
        $this->assertNotEmpty($message512->getSignature());
    }
}
