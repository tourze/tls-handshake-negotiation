<?php

namespace Tourze\TLSHandshakeNegotiation\Tests\Extension;

use Tourze\TLSHandshakeNegotiation\Extension\AbstractExtension;
use Tourze\TLSHandshakeNegotiation\Extension\ExtensionType;

/**
 * 用于测试的具体扩展实现
 */
class TestExtension extends AbstractExtension
{
    public function getType(): ExtensionType
    {
        return ExtensionType::SERVER_NAME;
    }

    public function encode(): string
    {
        return $this->encodeUint16(strlen($this->data ?? '')) . ($this->data ?? '');
    }

    public static function decode(string $data): static
    {
        $offset = 0;
        $lengthResult = self::decodeUint16($data, $offset);
        $length = $lengthResult['value'];
        $offset = $lengthResult['offset'];

        /** @phpstan-ignore-next-line */
        $extension = new static();
        if ($length > 0) {
            $extension->setData(substr($data, $offset, $length));
        }

        return $extension;
    }

    // 暴露受保护的方法用于测试
    public function testEncodeUint16(int $value): string
    {
        return $this->encodeUint16($value);
    }

    /**
     * @return array{value: int, offset: int}
     */
    public static function testDecodeUint16(string $data, int $offset): array
    {
        return self::decodeUint16($data, $offset);
    }
}
