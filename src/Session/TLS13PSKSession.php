<?php

namespace Tourze\TLSHandshakeNegotiation\Session;

/**
 * TLS 1.3 PSK会话类
 *
 * 用于协商阶段的简化版本
 */
class TLS13PSKSession
{
    /**
     * 构造函数
     *
     * @param string $sessionId   会话ID
     * @param string $pskIdentity PSK身份
     */
    public function __construct(
        private string $sessionId = '',
        private string $pskIdentity = '',
    ) {
    }

    /**
     * 获取PSK身份
     *
     * @return string PSK身份
     */
    public function getPskIdentity(): string
    {
        return $this->pskIdentity;
    }

    /**
     * 设置PSK身份
     *
     * @param string $pskIdentity PSK身份
     */
    public function setPskIdentity(string $pskIdentity): void
    {
        $this->pskIdentity = $pskIdentity;
    }

    /**
     * 获取会话ID
     *
     * @return string 会话ID
     */
    public function getSessionId(): string
    {
        return $this->sessionId;
    }
}
