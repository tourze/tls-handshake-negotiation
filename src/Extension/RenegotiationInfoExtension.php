<?php

namespace Tourze\TLSHandshakeNegotiation\Extension;

use Tourze\TLSHandshakeNegotiation\Exception\InvalidArgumentException;

/**
 * 安全重协商信息扩展
 *
 * 实现RFC 5746规定的TLS安全重协商扩展
 * 该扩展用于防止TLS重协商中的中间人攻击
 */
class RenegotiationInfoExtension extends AbstractExtension
{
    /**
     * 重协商连接数据
     *
     * 初始握手时为空
     * 重协商时，客户端提供已验证的finished消息
     */
    private string $renegotiatedConnection = '';

    /**
     * 构造函数
     */
    public function __construct()
    {
    }

    /**
     * 获取扩展类型
     *
     * @return ExtensionType 扩展类型
     */
    public function getType(): ExtensionType
    {
        return ExtensionType::RENEGOTIATION_INFO;
    }

    /**
     * 设置重协商连接数据
     *
     * @param string $data 重协商连接数据
     */
    public function setRenegotiatedConnection(string $data): void
    {
        $this->renegotiatedConnection = $data;
    }

    /**
     * 获取重协商连接数据
     *
     * @return string 重协商连接数据
     */
    public function getRenegotiatedConnection(): string
    {
        return $this->renegotiatedConnection;
    }

    /**
     * 将扩展数据序列化为二进制形式
     *
     * @return string 序列化后的二进制数据
     */
    public function encode(): string
    {
        // 重协商信息格式:
        // 1字节长度 + 数据
        $length = strlen($this->renegotiatedConnection);

        return chr($length) . $this->renegotiatedConnection;
    }

    /**
     * 从二进制数据反序列化扩展
     *
     * @param string $data 二进制数据
     *
     * @return static 解析后的扩展对象
     *
     * @throws \InvalidArgumentException 数据无效时抛出
     */
    public static function decode(string $data): static
    {
        if (strlen($data) < 1) {
            throw new InvalidArgumentException('安全重协商扩展数据不完整');
        }

        // 读取长度字节
        $length = ord($data[0]);

        // 验证数据长度
        if (strlen($data) - 1 < $length) {
            throw new InvalidArgumentException('安全重协商扩展数据长度与实际不符');
        }

        /** @phpstan-ignore-next-line */
        $extension = new static();
        if ($length > 0) {
            $extension->setRenegotiatedConnection(substr($data, 1, $length));
        }

        return $extension;
    }
}
