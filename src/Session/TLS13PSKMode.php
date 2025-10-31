<?php

namespace Tourze\TLSHandshakeNegotiation\Session;

use Tourze\TLSHandshakeNegotiation\Exception\InvalidArgumentException;

/**
 * TLS 1.3 PSK模式常量类
 */
class TLS13PSKMode
{
    /**
     * PSK-only密钥交换模式
     * 只使用PSK不进行ECDHE
     */
    public const PSK_KE = 0;

    /**
     * PSK和DH组合密钥交换模式(推荐)
     * 同时使用PSK和ECDHE提供前向保密性
     */
    public const PSK_DHE_KE = 1;

    /**
     * 检查PSK模式是否有效
     *
     * @param int $mode 要检查的模式
     *
     * @return bool 是否有效
     */
    public static function isValidMode(int $mode): bool
    {
        return self::PSK_KE === $mode || self::PSK_DHE_KE === $mode;
    }

    /**
     * 获取PSK模式名称
     *
     * @param int $mode PSK模式
     *
     * @return string 模式名称
     *
     * @throws InvalidArgumentException 如果模式无效
     */
    public static function getModeName(int $mode): string
    {
        return match ($mode) {
            self::PSK_KE => 'psk_ke',
            self::PSK_DHE_KE => 'psk_dhe_ke',
            default => throw new InvalidArgumentException('无效的PSK模式: ' . $mode),
        };
    }

    /**
     * 检查是否为纯PSK模式（不使用DH）
     *
     * @param int $mode PSK模式
     *
     * @return bool 是否为纯PSK模式
     */
    public static function isPSKOnlyMode(int $mode): bool
    {
        return self::PSK_KE === $mode;
    }

    /**
     * 获取所有可能的PSK模式
     *
     * @return array<int> 所有PSK模式
     */
    public static function getAllModes(): array
    {
        return [self::PSK_KE, self::PSK_DHE_KE];
    }
}
