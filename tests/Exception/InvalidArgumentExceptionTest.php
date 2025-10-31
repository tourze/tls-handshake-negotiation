<?php

namespace Tourze\TLSHandshakeNegotiation\Tests\Exception;

use PHPUnit\Framework\Attributes\CoversClass;
use Tourze\PHPUnitBase\AbstractExceptionTestCase;
use Tourze\TLSHandshakeNegotiation\Exception\InvalidArgumentException;

/**
 * 无效参数异常测试类
 *
 * @internal
 */
#[CoversClass(InvalidArgumentException::class)]
final class InvalidArgumentExceptionTest extends AbstractExceptionTestCase
{
    /**
     * 测试创建异常实例
     */
    public function testCreateException(): void
    {
        $message = '参数无效';
        $code = 200;
        $previous = new \Exception('Previous exception');

        $exception = new InvalidArgumentException($message, $code, $previous);

        $this->assertInstanceOf(InvalidArgumentException::class, $exception);
        $this->assertInstanceOf(\InvalidArgumentException::class, $exception);
        $this->assertEquals($message, $exception->getMessage());
        $this->assertEquals($code, $exception->getCode());
        $this->assertSame($previous, $exception->getPrevious());
    }

    /**
     * 测试默认参数
     */
    public function testDefaultParameters(): void
    {
        $exception = new InvalidArgumentException('Invalid parameter');

        $this->assertEquals('Invalid parameter', $exception->getMessage());
        $this->assertEquals(0, $exception->getCode());
        $this->assertNull($exception->getPrevious());
    }

    /**
     * 测试抛出和捕获异常
     */
    public function testThrowAndCatch(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('密钥长度不符合要求');

        throw new InvalidArgumentException('密钥长度不符合要求');
    }

    /**
     * 测试异常继承关系
     */
    public function testInheritance(): void
    {
        $exception = new InvalidArgumentException('Test');

        // 应该继承自PHP内置的InvalidArgumentException
        $this->assertInstanceOf(\InvalidArgumentException::class, $exception);
        // 同时也是Exception的实例
        $this->assertInstanceOf(\Exception::class, $exception);
    }
}
