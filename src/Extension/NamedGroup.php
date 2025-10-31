<?php

namespace Tourze\TLSHandshakeNegotiation\Extension;

use Tourze\EnumExtra\Itemable;
use Tourze\EnumExtra\ItemTrait;
use Tourze\EnumExtra\Labelable;
use Tourze\EnumExtra\Selectable;
use Tourze\EnumExtra\SelectTrait;

/**
 * TLS命名组（曲线组或DHE组）枚举
 *
 * 参考RFC 8446和RFC 7919
 */
enum NamedGroup: int implements Itemable, Labelable, Selectable
{
    use ItemTrait;
    use SelectTrait;
    // 椭圆曲线组
    /**
     * secp256r1 (NIST P-256)
     */
    case SECP256R1 = 0x0017;

    /**
     * secp384r1 (NIST P-384)
     */
    case SECP384R1 = 0x0018;

    /**
     * secp521r1 (NIST P-521)
     */
    case SECP521R1 = 0x0019;

    /**
     * x25519 (高性能曲线，TLS 1.3推荐)
     */
    case X25519 = 0x001D;

    /**
     * x448 (高性能曲线)
     */
    case X448 = 0x001E;

    // 有限域DHE组 (RFC 7919)
    /**
     * ffdhe2048
     */
    case FFDHE2048 = 0x0100;

    /**
     * ffdhe3072
     */
    case FFDHE3072 = 0x0101;

    /**
     * ffdhe4096
     */
    case FFDHE4096 = 0x0102;

    /**
     * ffdhe6144
     */
    case FFDHE6144 = 0x0103;

    /**
     * ffdhe8192
     */
    case FFDHE8192 = 0x0104;

    /**
     * 获取命名组的名称
     *
     * @return string 命名组名称
     */
    public function getName(): string
    {
        return match ($this) {
            self::SECP256R1 => 'secp256r1',
            self::SECP384R1 => 'secp384r1',
            self::SECP521R1 => 'secp521r1',
            self::X25519 => 'x25519',
            self::X448 => 'x448',
            self::FFDHE2048 => 'ffdhe2048',
            self::FFDHE3072 => 'ffdhe3072',
            self::FFDHE4096 => 'ffdhe4096',
            self::FFDHE6144 => 'ffdhe6144',
            self::FFDHE8192 => 'ffdhe8192',
        };
    }

    /**
     * 检查组是否为椭圆曲线组
     *
     * @return bool 是否为椭圆曲线组
     */
    public function isECGroup(): bool
    {
        return match ($this) {
            self::SECP256R1,
            self::SECP384R1,
            self::SECP521R1,
            self::X25519,
            self::X448 => true,
            default => false,
        };
    }

    /**
     * 检查组是否为有限域DHE组
     *
     * @return bool 是否为DHE组
     */
    public function isDHEGroup(): bool
    {
        return match ($this) {
            self::FFDHE2048,
            self::FFDHE3072,
            self::FFDHE4096,
            self::FFDHE6144,
            self::FFDHE8192 => true,
            default => false,
        };
    }

    /**
     * 根据TLS版本获取推荐的命名组列表
     *
     * @param int $tlsVersion TLS版本
     *
     * @return array<self> 推荐的命名组列表
     */
    public static function getRecommendedGroups(int $tlsVersion): array
    {
        if ($tlsVersion >= 0x0304) { // TLS 1.3+
            return [
                self::X25519,    // 性能最佳
                self::SECP256R1, // 广泛支持
                self::X448,      // 更高安全性
                self::SECP384R1,
                self::SECP521R1,
                self::FFDHE2048,
                self::FFDHE3072,
            ];
        }   // TLS 1.2

        return [
            self::SECP256R1, // 最广泛支持
            self::X25519,    // 如果支持则优先
            self::SECP384R1,
            self::FFDHE2048,
            self::FFDHE3072,
        ];
    }

    /**
     * 获取组的密钥长度（以字节为单位）
     *
     * @return int 密钥长度
     */
    public function getKeyLength(): int
    {
        return match ($this) {
            self::SECP256R1 => 32,
            self::SECP384R1 => 48,
            self::SECP521R1 => 66,
            self::X25519 => 32,
            self::X448 => 56,
            self::FFDHE2048 => 256,
            self::FFDHE3072 => 384,
            self::FFDHE4096 => 512,
            self::FFDHE6144 => 768,
            self::FFDHE8192 => 1024,
        };
    }

    public function getLabel(): string
    {
        return $this->name;
    }
}
