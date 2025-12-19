<?php

namespace Tourze\TLSHandshakeNegotiation\Extension;

use Tourze\TLSHandshakeNegotiation\Exception\InvalidArgumentException;

/**
 * 预共享密钥扩展
 *
 * TLS 1.3中引入的扩展，用于实现PSK功能
 *
 * 参考：RFC 8446 (TLS 1.3) Section 4.2.11
 */
class PreSharedKeyExtension extends AbstractExtension
{
    /**
     * PSK标识列表
     *
     * @var array<PSKIdentity>
     */
    private array $identities = [];

    /**
     * PSK绑定器列表
     *
     * @var array<string>
     */
    private array $binders = [];

    /**
     * 服务器选定的标识索引
     */
    private int $selectedIdentity = 0;

    /**
     * 构造函数
     *
     * @param bool $isServerFormat 是否为服务器格式（服务器格式只包含选定的标识索引）
     */
    public function __construct(
        private readonly bool $isServerFormat = false,
    ) {
    }

    /**
     * 获取扩展类型
     *
     * @return ExtensionType 扩展类型
     */
    public function getType(): ExtensionType
    {
        return ExtensionType::PRE_SHARED_KEY;
    }

    /**
     * 检查是否为服务器格式
     *
     * @return bool 是否为服务器格式
     */
    public function isServerFormat(): bool
    {
        return $this->isServerFormat;
    }

    /**
     * 获取PSK标识列表
     *
     * @return array<PSKIdentity> PSK标识列表
     */
    public function getIdentities(): array
    {
        return $this->identities;
    }

    /**
     * 设置PSK标识列表
     *
     * @param array<PSKIdentity> $identities PSK标识列表
     */
    public function setIdentities(array $identities): void
    {
        $this->identities = $identities;
    }

    /**
     * 添加PSK标识
     *
     * @param PSKIdentity $identity PSK标识
     */
    public function addIdentity(PSKIdentity $identity): self
    {
        $this->identities[] = $identity;

        return $this;
    }

    /**
     * 获取PSK绑定器列表
     *
     * @return array<string> PSK绑定器列表
     */
    public function getBinders(): array
    {
        return $this->binders;
    }

    /**
     * 设置PSK绑定器列表
     *
     * @param array<string> $binders PSK绑定器列表
     */
    public function setBinders(array $binders): void
    {
        $this->binders = $binders;
    }

    /**
     * 添加PSK绑定器
     *
     * @param string $binder PSK绑定器
     */
    public function addBinder(string $binder): self
    {
        $this->binders[] = $binder;

        return $this;
    }

    /**
     * 获取服务器选定的标识索引
     *
     * @return int 服务器选定的标识索引
     */
    public function getSelectedIdentity(): int
    {
        return $this->selectedIdentity;
    }

    /**
     * 设置服务器选定的标识索引
     *
     * @param int $selectedIdentity 服务器选定的标识索引
     */
    public function setSelectedIdentity(int $selectedIdentity): void
    {
        $this->selectedIdentity = $selectedIdentity;
    }

    /**
     * 将扩展编码为二进制数据
     *
     * 格式（客户端）：
     * struct {
     *     PskIdentity identities<7..2^16-1>;
     *     PskBinderEntry binders<33..2^16-1>;
     * } OfferedPsks;
     *
     * struct {
     *     opaque identity<1..2^16-1>;
     *     uint32 obfuscated_ticket_age;
     * } PskIdentity;
     *
     * struct {
     *     opaque binder<32..255>;
     * } PskBinderEntry;
     *
     * 格式（服务器）：
     * struct {
     *     uint16 selected_identity;
     * } PreSharedKeyServerHello;
     *
     * @return string 编码后的二进制数据
     */
    public function encode(): string
    {
        if ($this->isServerFormat) {
            // 服务器格式
            return $this->encodeUint16($this->selectedIdentity);
        }
        // 客户端格式
        $result = '';

        // 编码标识列表
        $identitiesData = '';
        foreach ($this->identities as $identity) {
            // 标识数据长度
            $identitiesData .= $this->encodeUint16(strlen($identity->getIdentity()));

            // 标识数据
            $identitiesData .= $identity->getIdentity();

            // 模糊化的票据年龄
            $identitiesData .= pack('N', $identity->getObfuscatedTicketAge());
        }

        // 标识列表长度
        $result .= $this->encodeUint16(strlen($identitiesData));

        // 标识列表数据
        $result .= $identitiesData;

        // 编码绑定器列表
        $bindersData = '';
        foreach ($this->binders as $binder) {
            // 绑定器长度
            $bindersData .= pack('C', strlen($binder));

            // 绑定器数据
            $bindersData .= $binder;
        }

        // 绑定器列表长度
        $result .= $this->encodeUint16(strlen($bindersData));

        // 绑定器列表数据
        $result .= $bindersData;

        return $result;
    }

    /**
     * 从二进制数据解码扩展
     *
     * @param string $data           二进制数据
     * @param bool   $isServerFormat 是否为服务器格式
     *
     * @return static 解码后的扩展对象
     *
     * @throws InvalidArgumentException 如果数据格式无效
     */
    public static function decode(string $data, bool $isServerFormat = false): static
    {
        $extension = new self($isServerFormat);

        if ($isServerFormat) {
            self::decodeServerFormat($extension, $data);
        } else {
            self::decodeClientFormat($extension, $data);
        }

        return $extension;
    }

    /**
     * 解码服务器格式的PreSharedKey扩展
     *
     * @param PreSharedKeyExtension $extension 扩展对象
     * @param string                $data      二进制数据
     *
     * @throws InvalidArgumentException 如果数据格式无效
     */
    private static function decodeServerFormat(PreSharedKeyExtension $extension, string $data): void
    {
        if (strlen($data) < 2) {
            throw new InvalidArgumentException('PreSharedKey server extension data too short');
        }

        $offset = 0;

        // 选定的标识索引
        ['value' => $selectedIdentity, 'offset' => $offset] = self::decodeUint16($data, $offset);
        $extension->setSelectedIdentity($selectedIdentity);
    }

    /**
     * 解码客户端格式的PreSharedKey扩展
     *
     * @param PreSharedKeyExtension $extension 扩展对象
     * @param string                $data      二进制数据
     *
     * @throws InvalidArgumentException 如果数据格式无效
     */
    private static function decodeClientFormat(PreSharedKeyExtension $extension, string $data): void
    {
        if (strlen($data) < 4) { // 至少需要2字节的标识列表长度和2字节的绑定器列表长度
            throw new InvalidArgumentException('PreSharedKey client extension data too short');
        }

        $offset = 0;

        // 解析标识列表
        $offset = self::decodeIdentitiesList($extension, $data, $offset);

        // 解析绑定器列表
        self::decodeBindersList($extension, $data, $offset);
    }

    /**
     * 解码标识列表
     *
     * @param PreSharedKeyExtension $extension 扩展对象
     * @param string                $data      二进制数据
     * @param int                   $offset    当前偏移量
     *
     * @return int 新的偏移量
     *
     * @throws InvalidArgumentException 如果数据格式无效
     */
    private static function decodeIdentitiesList(PreSharedKeyExtension $extension, string $data, int $offset): int
    {
        // 标识列表长度
        ['value' => $identitiesLength, 'offset' => $offset] = self::decodeUint16($data, $offset);

        // 检查数据长度是否足够
        if ($offset + $identitiesLength > strlen($data)) {
            throw new InvalidArgumentException('PreSharedKey client extension identities length mismatch');
        }

        // 解析标识列表
        $identitiesEnd = $offset + $identitiesLength;
        while ($offset < $identitiesEnd) {
            $offset = self::decodeIdentity($extension, $data, $offset, $identitiesEnd);
        }

        return $offset;
    }

    /**
     * 解码单个标识
     *
     * @param PreSharedKeyExtension $extension     扩展对象
     * @param string                $data          二进制数据
     * @param int                   $offset        当前偏移量
     * @param int                   $identitiesEnd 标识列表结束位置
     *
     * @return int 新的偏移量
     *
     * @throws InvalidArgumentException 如果数据格式无效
     */
    private static function decodeIdentity(PreSharedKeyExtension $extension, string $data, int $offset, int $identitiesEnd): int
    {
        // 标识长度
        if ($offset + 2 > $identitiesEnd) {
            throw new InvalidArgumentException('PreSharedKey client extension identity length field incomplete');
        }
        ['value' => $identityLength, 'offset' => $offset] = self::decodeUint16($data, $offset);

        // 检查数据长度是否足够
        if ($offset + $identityLength + 4 > $identitiesEnd) {
            throw new InvalidArgumentException('PreSharedKey client extension identity data incomplete');
        }

        // 标识数据
        $identityData = substr($data, $offset, $identityLength);
        $offset += $identityLength;

        // 模糊化的票据年龄
        $unpacked = unpack('N', substr($data, $offset, 4));
        if (false === $unpacked) {
            throw new InvalidArgumentException('Failed to unpack obfuscated ticket age');
        }
        $obfuscatedTicketAge = $unpacked[1];
        $offset += 4;

        // 创建标识并添加到扩展
        $identity = new PSKIdentity();
        $identity->setIdentity($identityData);
        $identity->setObfuscatedTicketAge($obfuscatedTicketAge);
        $extension->addIdentity($identity);

        return $offset;
    }

    /**
     * 解码绑定器列表
     *
     * @param PreSharedKeyExtension $extension 扩展对象
     * @param string                $data      二进制数据
     * @param int                   $offset    当前偏移量
     *
     * @throws InvalidArgumentException 如果数据格式无效
     */
    private static function decodeBindersList(PreSharedKeyExtension $extension, string $data, int $offset): void
    {
        // 绑定器列表长度
        ['value' => $bindersLength, 'offset' => $offset] = self::decodeUint16($data, $offset);

        // 检查数据长度是否足够
        if ($offset + $bindersLength > strlen($data)) {
            throw new InvalidArgumentException('PreSharedKey client extension binders length mismatch');
        }

        // 解析绑定器列表
        $bindersEnd = $offset + $bindersLength;
        while ($offset < $bindersEnd) {
            $offset = self::decodeBinder($extension, $data, $offset, $bindersEnd);
        }
    }

    /**
     * 解码单个绑定器
     *
     * @param PreSharedKeyExtension $extension  扩展对象
     * @param string                $data       二进制数据
     * @param int                   $offset     当前偏移量
     * @param int                   $bindersEnd 绑定器列表结束位置
     *
     * @return int 新的偏移量
     *
     * @throws InvalidArgumentException 如果数据格式无效
     */
    private static function decodeBinder(PreSharedKeyExtension $extension, string $data, int $offset, int $bindersEnd): int
    {
        // 绑定器长度
        if ($offset + 1 > $bindersEnd) {
            throw new InvalidArgumentException('PreSharedKey client extension binder length field incomplete');
        }
        $unpacked = unpack('C', substr($data, $offset, 1));
        if (false === $unpacked) {
            throw new InvalidArgumentException('Failed to unpack binder length');
        }
        $binderLength = $unpacked[1];
        ++$offset;

        // 检查数据长度是否足够
        if ($offset + $binderLength > $bindersEnd) {
            throw new InvalidArgumentException('PreSharedKey client extension binder data incomplete');
        }

        // 绑定器数据
        $binderData = substr($data, $offset, $binderLength);
        $offset += $binderLength;

        // 添加绑定器到扩展
        $extension->addBinder($binderData);

        return $offset;
    }

    /**
     * 检查扩展是否适用于指定的TLS版本
     *
     * pre_shared_key扩展仅适用于TLS 1.3
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
