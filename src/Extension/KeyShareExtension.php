<?php

namespace Tourze\TLSHandshakeNegotiation\Extension;

use Tourze\TLSHandshakeNegotiation\Exception\InvalidArgumentException;

/**
 * 密钥共享扩展
 *
 * TLS 1.3中引入的扩展，用于传输密钥协商参数
 *
 * 参考：RFC 8446 (TLS 1.3) Section 4.2.8
 */
class KeyShareExtension extends AbstractExtension
{
    /**
     * 密钥共享条目列表
     *
     * @var array<KeyShareEntry>
     */
    private array $entries = [];

    /**
     * 构造函数
     *
     * @param bool $isServerFormat 是否为服务器格式（服务器格式只包含一个条目，且没有长度前缀）
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
        return ExtensionType::KEY_SHARE;
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
     * 获取密钥共享条目列表
     *
     * @return array<KeyShareEntry> 密钥共享条目列表
     */
    public function getEntries(): array
    {
        return $this->entries;
    }

    /**
     * 设置密钥共享条目列表
     *
     * @param array<KeyShareEntry> $entries 密钥共享条目列表
     */
    public function setEntries(array $entries): void
    {
        $this->entries = $entries;
    }

    /**
     * 添加密钥共享条目
     *
     * @param KeyShareEntry $entry 密钥共享条目
     */
    public function addEntry(KeyShareEntry $entry): self
    {
        $this->entries[] = $entry;

        return $this;
    }

    /**
     * 根据组标识符获取密钥共享条目
     *
     * @param int|NamedGroup $group 组标识符
     *
     * @return KeyShareEntry|null 如果找到返回条目，否则返回null
     */
    public function getEntryByGroup(int|NamedGroup $group): ?KeyShareEntry
    {
        $groupValue = $group instanceof NamedGroup ? $group->value : $group;

        foreach ($this->entries as $entry) {
            if ($entry->getGroup() === $groupValue) {
                return $entry;
            }
        }

        return null;
    }

    /**
     * 将扩展编码为二进制数据
     *
     * 格式（客户端）：
     * struct {
     *     uint16 client_shares_length;
     *     KeyShareEntry client_shares[client_shares_length];
     * } KeyShareClientHello;
     *
     * 格式（服务器）：
     * struct {
     *     KeyShareEntry server_share;
     * } KeyShareServerHello;
     *
     * @return string 编码后的二进制数据
     */
    public function encode(): string
    {
        $result = '';

        // 编码所有条目
        $entriesData = '';
        foreach ($this->entries as $entry) {
            // 组标识符
            $entriesData .= $this->encodeUint16($entry->getGroup());

            // 密钥交换数据长度
            $entriesData .= $this->encodeUint16(strlen($entry->getKeyExchange()));

            // 密钥交换数据
            $entriesData .= $entry->getKeyExchange();
        }

        // 服务器格式不包含条目列表长度
        if (!$this->isServerFormat) {
            // 条目列表长度（按字节计）
            $result .= $this->encodeUint16(strlen($entriesData));
        }

        // 条目列表数据
        $result .= $entriesData;

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
     * 解码服务器格式的KeyShare扩展
     *
     * @param KeyShareExtension $extension 扩展对象
     * @param string            $data      二进制数据
     *
     * @throws InvalidArgumentException 如果数据格式无效
     */
    private static function decodeServerFormat(KeyShareExtension $extension, string $data): void
    {
        // 服务器格式只有一个条目，没有长度前缀
        if (strlen($data) < 4) { // 至少需要2字节的组标识符和2字节的密钥交换数据长度
            throw new InvalidArgumentException('KeyShare server extension data too short');
        }

        $offset = 0;
        $entry = new KeyShareEntry();

        // 组标识符
        $groupResult = self::decodeUint16($data, $offset);
        $group = $groupResult['value'];
        $offset = $groupResult['offset'];
        $entry->setGroup($group);

        // 密钥交换数据长度
        $keyLengthResult = self::decodeUint16($data, $offset);
        $keyExchangeLength = $keyLengthResult['value'];
        $offset = $keyLengthResult['offset'];

        // 检查数据长度是否足够
        if ($offset + $keyExchangeLength > strlen($data)) {
            throw new InvalidArgumentException('KeyShare server extension key exchange data incomplete');
        }

        // 密钥交换数据
        $keyExchange = substr($data, $offset, $keyExchangeLength);
        $entry->setKeyExchange($keyExchange);

        // 添加条目
        $extension->addEntry($entry);
    }

    /**
     * 解码客户端格式的KeyShare扩展
     *
     * @param KeyShareExtension $extension 扩展对象
     * @param string            $data      二进制数据
     *
     * @throws InvalidArgumentException 如果数据格式无效
     */
    private static function decodeClientFormat(KeyShareExtension $extension, string $data): void
    {
        // 客户端格式有长度前缀和多个条目
        if (strlen($data) < 2) { // 至少需要2字节的条目列表长度
            throw new InvalidArgumentException('KeyShare client extension data too short');
        }

        $offset = 0;

        // 条目列表长度
        $lengthResult = self::decodeUint16($data, $offset);
        $entriesLength = $lengthResult['value'];
        $offset = $lengthResult['offset'];

        // 检查数据长度是否一致
        if ($offset + $entriesLength > strlen($data)) {
            throw new InvalidArgumentException('KeyShare client extension entries length mismatch');
        }

        // 解析条目列表
        $entriesEnd = $offset + $entriesLength;
        while ($offset < $entriesEnd) {
            $entryResult = self::decodeKeyShareEntry($data, $offset, $entriesEnd);
            $extension->addEntry($entryResult['entry']);
            $offset = $entryResult['offset'];
        }
    }

    /**
     * 解码单个KeyShare条目
     *
     * @param string $data       二进制数据
     * @param int    $offset     当前偏移量
     * @param int    $entriesEnd 条目结束位置
     *
     * @return array{entry: KeyShareEntry, offset: int} 包含解码条目和新偏移量的数组
     *
     * @throws InvalidArgumentException 如果数据格式无效
     */
    private static function decodeKeyShareEntry(string $data, int $offset, int $entriesEnd): array
    {
        // 确保有足够的数据来解析条目头部
        if ($offset + 4 > $entriesEnd) {
            throw new InvalidArgumentException('KeyShare client extension entry header incomplete');
        }

        $entry = new KeyShareEntry();

        // 组标识符
        $groupResult = self::decodeUint16($data, $offset);
        $group = $groupResult['value'];
        $offset = $groupResult['offset'];
        $entry->setGroup($group);

        // 密钥交换数据长度
        $keyLengthResult = self::decodeUint16($data, $offset);
        $keyExchangeLength = $keyLengthResult['value'];
        $offset = $keyLengthResult['offset'];

        // 检查是否有足够的数据
        if ($offset + $keyExchangeLength > $entriesEnd) {
            throw new InvalidArgumentException('KeyShare client extension key exchange data incomplete');
        }

        // 密钥交换数据
        $keyExchange = substr($data, $offset, $keyExchangeLength);
        $offset += $keyExchangeLength;
        $entry->setKeyExchange($keyExchange);

        return ['entry' => $entry, 'offset' => $offset];
    }

    /**
     * 检查扩展是否适用于指定的TLS版本
     *
     * 密钥共享扩展仅适用于TLS 1.3
     *
     * @param string $tlsVersion TLS版本（例如："1.2", "1.3"）
     *
     * @return bool 是否适用
     */
    public function isApplicableForVersion(string $tlsVersion): bool
    {
        return '1.3' === $tlsVersion;
    }
}
