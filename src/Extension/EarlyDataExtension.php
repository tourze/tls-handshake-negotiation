<?php

namespace Tourze\TLSHandshakeNegotiation\Extension;

use Tourze\TLSHandshakeNegotiation\Exception\InvalidArgumentException;

/**
 * 早期数据扩展
 *
 * TLS 1.3中引入的扩展，用于支持0-RTT数据
 *
 * 参考：RFC 8446 (TLS 1.3) Section 4.2.10
 */
class EarlyDataExtension extends AbstractExtension
{
    /**
     * 扩展格式 - 客户端Hello
     */
    public const FORMAT_CLIENT_HELLO = 1;

    /**
     * 扩展格式 - 服务器Hello
     */
    public const FORMAT_SERVER_HELLO = 2;

    /**
     * 扩展格式 - 加密扩展
     */
    public const FORMAT_ENCRYPTED_EXTENSIONS = 3;

    /**
     * 扩展格式 - 新会话票据
     */
    public const FORMAT_NEW_SESSION_TICKET = 4;

    /**
     * 扩展格式
     */
    private int $format;

    /**
     * 最大早期数据大小
     *
     * 仅在新会话票据格式中使用
     */
    private int $maxEarlyDataSize = 0;

    /**
     * 构造函数
     *
     * @param int $format 扩展格式
     */
    public function __construct(int $format = self::FORMAT_CLIENT_HELLO)
    {
        $this->format = $format;
    }

    /**
     * 获取扩展类型
     *
     * @return ExtensionType 扩展类型
     */
    public function getType(): ExtensionType
    {
        return ExtensionType::EARLY_DATA;
    }

    /**
     * 获取扩展格式
     *
     * @return int 扩展格式
     */
    public function getFormat(): int
    {
        return $this->format;
    }

    /**
     * 设置扩展格式
     *
     * @param int $format 扩展格式
     */
    public function setFormat(int $format): void
    {
        $this->format = $format;
    }

    /**
     * 获取最大早期数据大小
     *
     * @return int 最大早期数据大小
     */
    public function getMaxEarlyDataSize(): int
    {
        return $this->maxEarlyDataSize;
    }

    /**
     * 设置最大早期数据大小
     *
     * @param int $maxEarlyDataSize 最大早期数据大小
     */
    public function setMaxEarlyDataSize(int $maxEarlyDataSize): void
    {
        $this->maxEarlyDataSize = $maxEarlyDataSize;
    }

    /**
     * 将扩展编码为二进制数据
     *
     * 格式（客户端/服务器/加密扩展）：
     * struct {} Empty;
     *
     * 格式（新会话票据）：
     * struct {
     *     uint32 max_early_data_size;
     * } EarlyDataIndication;
     *
     * @return string 编码后的二进制数据
     */
    public function encode(): string
    {
        if (self::FORMAT_NEW_SESSION_TICKET === $this->format) {
            // 新会话票据格式
            return pack('N', $this->maxEarlyDataSize);
        }

        // 其他格式（空）
        return '';
    }

    /**
     * 从二进制数据解码扩展
     *
     * @param string $data   二进制数据
     * @param int    $format 扩展格式
     *
     * @return static 解码后的扩展对象
     *
     * @throws InvalidArgumentException 如果数据格式无效
     */
    public static function decode(string $data, int $format = self::FORMAT_CLIENT_HELLO): static
    {
        /** @phpstan-ignore-next-line */
        $extension = new static($format);

        if (self::FORMAT_NEW_SESSION_TICKET === $format) {
            // 新会话票据格式
            if (strlen($data) < 4) {
                throw new InvalidArgumentException('EarlyData new session ticket extension data too short');
            }

            // 最大早期数据大小
            $unpacked = unpack('N', $data);
            if (false === $unpacked) {
                throw new InvalidArgumentException('无效的早期数据扩展格式');
            }
            $extension->setMaxEarlyDataSize($unpacked[1]);
        }
        // 其他格式不需要解析任何数据

        return $extension;
    }

    /**
     * 检查扩展是否适用于指定的TLS版本
     *
     * early_data扩展仅适用于TLS 1.3
     *
     * @param string $tlsVersion TLS版本
     *
     * @return bool 是否适用
     */
    public function isApplicableForVersion(string $tlsVersion): bool
    {
        return '1.3' === $tlsVersion;
    }
}
