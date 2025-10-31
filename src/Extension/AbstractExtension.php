<?php

namespace Tourze\TLSHandshakeNegotiation\Extension;

use Tourze\TLSHandshakeNegotiation\Exception\InvalidArgumentException;

/**
 * TLS扩展抽象基类
 *
 * 提供扩展的基本功能
 */
abstract class AbstractExtension implements ExtensionInterface
{
    /**
     * 扩展数据（二进制格式）
     */
    protected ?string $data = null;

    /**
     * 获取扩展类型
     *
     * @return ExtensionType 扩展类型
     */
    abstract public function getType(): ExtensionType;

    /**
     * 获取扩展数据
     *
     * @return string|null 扩展数据
     */
    public function getData(): ?string
    {
        return $this->data;
    }

    /**
     * 设置扩展数据
     *
     * @param string|null $data 扩展数据
     */
    public function setData(?string $data): void
    {
        $this->data = $data;
    }

    /**
     * 将16位无符号整数编码为二进制数据（网络字节序）
     *
     * @param int $value 要编码的整数
     *
     * @return string 二进制数据
     */
    protected function encodeUint16(int $value): string
    {
        return pack('n', $value);
    }

    /**
     * 从二进制数据解码16位无符号整数（网络字节序）
     *
     * @param string $data   二进制数据
     * @param int    $offset 当前偏移量
     *
     * @return array{value: int, offset: int} 包含解码值和新偏移量的数组
     */
    protected static function decodeUint16(string $data, int $offset): array
    {
        $unpacked = unpack('n', substr($data, $offset, 2));
        if (false === $unpacked) {
            throw new InvalidArgumentException('Failed to unpack uint16');
        }
        $value = $unpacked[1];
        $newOffset = $offset + 2;

        return ['value' => $value, 'offset' => $newOffset];
    }

    /**
     * 检查扩展是否适用于指定的TLS版本
     * 默认所有版本都支持，子类可以重写此方法以限制版本支持
     *
     * @param string $tlsVersion TLS版本（例如："1.2", "1.3"）
     *
     * @return bool 是否适用
     */
    public function isApplicableForVersion(string $tlsVersion): bool
    {
        return true;
    }

    /**
     * 将扩展编码为二进制数据
     *
     * @return string 编码后的二进制数据
     */
    abstract public function encode(): string;

    /**
     * 从二进制数据解码扩展
     *
     * @param string $data 二进制数据
     *
     * @return static 解码后的扩展对象
     */
    abstract public static function decode(string $data): static;
}
