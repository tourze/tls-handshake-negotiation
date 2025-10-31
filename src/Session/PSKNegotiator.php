<?php

namespace Tourze\TLSHandshakeNegotiation\Session;

use Tourze\TLSHandshakeNegotiation\Exception\InvalidArgumentException;

/**
 * PSK协商器
 *
 * 负责TLS 1.3中PSK身份和模式的选择与协商
 */
class PSKNegotiator
{
    /**
     * 首选PSK模式
     */
    private int $preferredMode = TLS13PSKMode::PSK_DHE_KE;

    /**
     * 是否强制使用首选模式
     */
    private bool $requirePreferredMode = false;

    /**
     * 协商后的PSK身份
     */
    private ?string $negotiatedPSK = null;

    /**
     * 协商后的PSK模式
     */
    private ?int $negotiatedMode = null;

    /**
     * 构造函数
     *
     * @param PSKHandler $pskHandler PSK处理器
     */
    public function __construct(
        private readonly PSKHandler $pskHandler,
    ) {
    }

    /**
     * 选择最佳的PSK身份
     *
     * 从客户端提供的PSK列表中选择第一个有效的PSK
     *
     * @param array<string> $clientPSKs 客户端PSK身份列表
     *
     * @return string|null 选择的PSK身份，无匹配则返回null
     */
    public function selectBestPSK(array $clientPSKs): ?string
    {
        foreach ($clientPSKs as $pskIdentity) {
            if ($this->pskHandler->hasPSK($pskIdentity)) {
                return $pskIdentity;
            }
        }

        return null;
    }

    /**
     * 选择最佳的PSK模式
     *
     * 根据服务器首选和客户端支持的模式选择最佳PSK模式
     *
     * @param array<int> $clientModes 客户端支持的PSK模式列表
     *
     * @return int|null 选择的PSK模式，无匹配则返回null
     */
    public function selectBestPSKMode(array $clientModes): ?int
    {
        // 检查客户端是否支持我们首选的模式
        if (in_array($this->preferredMode, $clientModes, true)) {
            return $this->preferredMode;
        }

        // 如果要求必须使用首选模式，但客户端不支持，则返回null
        if ($this->requirePreferredMode) {
            return null;
        }

        // 否则尝试找到第一个有效的模式
        foreach ($clientModes as $mode) {
            if (TLS13PSKMode::isValidMode($mode)) {
                return $mode;
            }
        }

        return null;
    }

    /**
     * 设置首选PSK模式
     *
     * @param int $mode PSK模式
     *
     * @throws \InvalidArgumentException 如果模式无效
     */
    public function setPreferredMode(int $mode): void
    {
        if (!TLS13PSKMode::isValidMode($mode)) {
            throw new InvalidArgumentException('无效的PSK模式: ' . $mode);
        }

        $this->preferredMode = $mode;
    }

    /**
     * 设置是否必须使用首选模式
     *
     * @param bool $require 是否必须
     */
    public function setRequirePreferredMode(bool $require): void
    {
        $this->requirePreferredMode = $require;
    }

    /**
     * 获取首选PSK模式
     *
     * @return int PSK模式
     */
    public function getPreferredMode(): int
    {
        return $this->preferredMode;
    }

    /**
     * 是否必须使用首选模式
     *
     * @return bool 是否必须
     */
    public function isPreferredModeRequired(): bool
    {
        return $this->requirePreferredMode;
    }

    /**
     * 设置协商后的PSK身份
     *
     * @param string|null $pskIdentity PSK身份
     */
    public function setNegotiatedPSK(?string $pskIdentity): void
    {
        $this->negotiatedPSK = $pskIdentity;
    }

    /**
     * 获取协商后的PSK身份
     *
     * @return string|null PSK身份
     */
    public function getNegotiatedPSK(): ?string
    {
        return $this->negotiatedPSK;
    }

    /**
     * 设置协商后的PSK模式
     *
     * @param int|null $mode PSK模式
     */
    public function setNegotiatedMode(?int $mode): void
    {
        $this->negotiatedMode = $mode;
    }

    /**
     * 获取协商后的PSK模式
     *
     * @return int|null PSK模式
     */
    public function getNegotiatedMode(): ?int
    {
        return $this->negotiatedMode;
    }

    /**
     * 检查PSK协商是否成功
     *
     * 协商成功需要同时具有有效的PSK身份和模式
     *
     * @return bool 是否成功
     */
    public function isPSKNegotiationSuccessful(): bool
    {
        return null !== $this->negotiatedPSK
               && null !== $this->negotiatedMode
               && TLS13PSKMode::isValidMode($this->negotiatedMode);
    }
}
