<?php

namespace Tourze\TLSHandshakeNegotiation\Extension;

/**
 * TLS扩展接口
 *
 * 定义所有TLS协议扩展的通用接口
 */
interface ExtensionInterface
{
    /**
     * 获取扩展类型
     *
     * @return ExtensionType 扩展类型
     */
    public function getType(): ExtensionType;

    /**
     * 将扩展编码为二进制数据
     *
     * @return string 编码后的二进制数据
     */
    public function encode(): string;

    /**
     * 从二进制数据解码扩展
     *
     * @param string $data 二进制数据
     *
     * @return static 解码后的扩展对象
     */
    public static function decode(string $data): static;

    /**
     * 检查扩展是否适用于指定的TLS版本
     *
     * @param string $tlsVersion TLS版本（例如："1.2", "1.3"）
     *
     * @return bool 是否适用
     */
    public function isApplicableForVersion(string $tlsVersion): bool;
}
