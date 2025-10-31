<?php

namespace Tourze\TLSHandshakeNegotiation\Tests\Extension;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshakeNegotiation\Extension\AbstractExtension;
use Tourze\TLSHandshakeNegotiation\Extension\ExtensionType;

/**
 * 抽象扩展类测试
 *
 * @internal
 */
#[CoversClass(AbstractExtension::class)]
final class AbstractExtensionTest extends TestCase
{
    private TestExtension $extension;

    protected function setUp(): void
    {
        parent::setUp();
        $this->extension = new TestExtension();
    }

    /**
     * 测试获取和设置扩展数据
     */
    public function testGetSetData(): void
    {
        $this->assertNull($this->extension->getData());

        $testData = 'test extension data';
        $this->extension->setData($testData);

        $this->assertEquals($testData, $this->extension->getData());

        $this->extension->setData(null);
        $this->assertNull($this->extension->getData());
    }

    /**
     * 测试版本适用性检查
     */
    public function testIsApplicableForVersion(): void
    {
        // 默认应该对所有版本都返回true
        $this->assertTrue($this->extension->isApplicableForVersion('1.2'));
        $this->assertTrue($this->extension->isApplicableForVersion('1.3'));
        $this->assertTrue($this->extension->isApplicableForVersion('any_version'));
    }

    /**
     * 测试16位无符号整数编码
     */
    public function testEncodeUint16(): void
    {
        // 测试各种值的编码
        $this->assertEquals("\x00\x00", $this->extension->testEncodeUint16(0));
        $this->assertEquals("\x00\xFF", $this->extension->testEncodeUint16(255));
        $this->assertEquals("\x01\x00", $this->extension->testEncodeUint16(256));
        $this->assertEquals("\xFF\xFF", $this->extension->testEncodeUint16(65535));
    }

    /**
     * 测试16位无符号整数解码
     */
    public function testDecodeUint16(): void
    {
        $data = "\x00\x00\x00\xFF\x01\x00\xFF\xFF";
        $offset = 0;

        $result1 = TestExtension::testDecodeUint16($data, $offset);
        $this->assertEquals(0, $result1['value']);
        $this->assertEquals(2, $result1['offset']);
        $offset = $result1['offset'];

        $result2 = TestExtension::testDecodeUint16($data, $offset);
        $this->assertEquals(255, $result2['value']);
        $this->assertEquals(4, $result2['offset']);
        $offset = $result2['offset'];

        $result3 = TestExtension::testDecodeUint16($data, $offset);
        $this->assertEquals(256, $result3['value']);
        $this->assertEquals(6, $result3['offset']);
        $offset = $result3['offset'];

        $result4 = TestExtension::testDecodeUint16($data, $offset);
        $this->assertEquals(65535, $result4['value']);
        $this->assertEquals(8, $result4['offset']);
    }

    /**
     * 测试获取扩展类型
     */
    public function testGetType(): void
    {
        $type = $this->extension->getType();
        $this->assertInstanceOf(ExtensionType::class, $type);
        $this->assertEquals(ExtensionType::SERVER_NAME, $type);
    }

    /**
     * 测试编码和解码往返
     */
    public function testEncodeDecodeRoundTrip(): void
    {
        $this->extension->setData('test data');
        $encoded = $this->extension->encode();

        $decoded = TestExtension::decode($encoded);
        $this->assertEquals('test data', $decoded->getData());
    }
}
