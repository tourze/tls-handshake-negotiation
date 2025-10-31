<?php

namespace Tourze\TLSHandshakeNegotiation\Tests\Exception;

use PHPUnit\Framework\Attributes\CoversClass;
use Tourze\PHPUnitBase\AbstractExceptionTestCase;
use Tourze\TLSHandshakeNegotiation\Exception\CertificateException;

/**
 * 证书异常测试类
 *
 * @internal
 */
#[CoversClass(CertificateException::class)]
final class CertificateExceptionTest extends AbstractExceptionTestCase
{
    /**
     * 测试创建异常实例
     */
    public function testCreateException(): void
    {
        $message = '证书验证失败';
        $code = 100;
        $previous = new \Exception('Previous exception');

        $exception = new CertificateException($message, $code, $previous);

        $this->assertInstanceOf(CertificateException::class, $exception);
        $this->assertInstanceOf(\Exception::class, $exception);
        $this->assertEquals($message, $exception->getMessage());
        $this->assertEquals($code, $exception->getCode());
        $this->assertSame($previous, $exception->getPrevious());
    }

    /**
     * 测试默认参数
     */
    public function testDefaultParameters(): void
    {
        $exception = new CertificateException('Test message');

        $this->assertEquals('Test message', $exception->getMessage());
        $this->assertEquals(0, $exception->getCode());
        $this->assertNull($exception->getPrevious());
    }

    /**
     * 测试抛出和捕获异常
     */
    public function testThrowAndCatch(): void
    {
        $this->expectException(CertificateException::class);
        $this->expectExceptionMessage('证书格式无效');

        throw new CertificateException('证书格式无效');
    }
}
