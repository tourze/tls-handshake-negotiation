<?php

namespace Tourze\TLSHandshakeNegotiation\Extension;

use Tourze\TLSHandshakeNegotiation\Exception\InvalidArgumentException;

/**
 * 支持的组扩展
 *
 * 用于表示客户端或服务器支持的椭圆曲线组和有限域DHE组
 * 在TLS 1.2中称为"elliptic_curves"，在TLS 1.3中改名为"supported_groups"
 *
 * 参考RFC 8446 4.2.7
 */
class SupportedGroupsExtension extends AbstractExtension
{
    /**
     * 支持的组列表
     *
     * @var array<NamedGroup>
     */
    private array $groups = [];

    /**
     * 构造函数
     *
     * @param array<NamedGroup>|null $groups 支持的组列表
     */
    public function __construct(?array $groups = null)
    {
        if (null !== $groups) {
            $this->groups = $groups;
        } else {
            // 默认添加推荐的组
            $this->groups = [];
            foreach (NamedGroup::getRecommendedGroups(0x0304) as $value) {
                if ($value instanceof NamedGroup) {
                    $this->groups[] = $value;
                } else {
                    $this->groups[] = NamedGroup::from($value);
                }
            }
        }
    }

    /**
     * 获取扩展类型
     *
     * @return ExtensionType 扩展类型
     */
    public function getType(): ExtensionType
    {
        return ExtensionType::SUPPORTED_GROUPS;
    }

    /**
     * 获取支持的组列表
     *
     * @return array<NamedGroup> 支持的组列表
     */
    public function getGroups(): array
    {
        return $this->groups;
    }

    /**
     * 设置支持的组列表
     *
     * @param array<NamedGroup> $groups 支持的组列表
     */
    public function setGroups(array $groups): void
    {
        $this->groups = $groups;
    }

    /**
     * 添加支持的组
     *
     * @param NamedGroup $group 要添加的组
     */
    public function addGroup(NamedGroup $group): void
    {
        if (!in_array($group, $this->groups, true)) {
            $this->groups[] = $group;
        }
    }

    /**
     * 移除支持的组
     *
     * @param NamedGroup $group 要移除的组
     */
    public function removeGroup(NamedGroup $group): void
    {
        $this->groups = array_filter(
            $this->groups,
            fn (NamedGroup $g) => $g !== $group
        );
    }

    /**
     * 获取仅椭圆曲线组
     *
     * @return array<NamedGroup> 椭圆曲线组列表
     */
    public function getECGroups(): array
    {
        return array_filter(
            $this->groups,
            fn (NamedGroup $group) => $group->isECGroup()
        );
    }

    /**
     * 获取仅DHE组
     *
     * @return array<NamedGroup> DHE组列表
     */
    public function getDHEGroups(): array
    {
        return array_filter(
            $this->groups,
            fn (NamedGroup $group) => $group->isDHEGroup()
        );
    }

    /**
     * 协商共同支持的组
     *
     * @param SupportedGroupsExtension $peerExtension 对端扩展
     *
     * @return array<NamedGroup> 协商结果，按照对端优先级排序
     */
    public function negotiate(SupportedGroupsExtension $peerExtension): array
    {
        $peerGroups = $peerExtension->getGroups();
        $negotiatedGroups = [];

        // 按照对端优先级选择共同支持的组
        foreach ($peerGroups as $group) {
            if (in_array($group, $this->groups, true)) {
                $negotiatedGroups[] = $group;
            }
        }

        return $negotiatedGroups;
    }

    /**
     * 将扩展编码为二进制数据
     *
     * @return string 编码后的二进制数据
     */
    public function encode(): string
    {
        $groupListData = '';

        // 编码所有支持的组
        foreach ($this->groups as $group) {
            $groupListData .= $this->encodeUint16($group->value);
        }

        // 编码支持的组扩展结构:
        // 2字节列表长度 + 组值列表
        $listLength = strlen($groupListData);

        return $this->encodeUint16($listLength) . $groupListData;
    }

    /**
     * 从二进制数据解码扩展
     *
     * @param string $data 二进制数据
     *
     * @return static 解码后的扩展对象
     *
     * @throws \InvalidArgumentException 数据无效时抛出
     */
    public static function decode(string $data): static
    {
        $offset = 0;
        /** @phpstan-ignore-next-line */
        $extension = new static([]);

        // 数据长度至少需要2字节
        if (strlen($data) < 2) {
            throw new InvalidArgumentException('支持的组扩展数据不完整');
        }

        // 读取列表长度
        ['value' => $listLength, 'offset' => $offset] = self::decodeUint16($data, $offset);

        // 验证数据长度
        if (strlen($data) - $offset < $listLength) {
            throw new InvalidArgumentException('支持的组扩展数据长度与实际不符');
        }

        // 读取所有组值
        $groups = [];
        $endOffset = $offset + $listLength;

        while ($offset < $endOffset) {
            if ($offset + 2 > $endOffset) {
                throw new InvalidArgumentException('支持的组数据格式错误');
            }

            ['value' => $groupValue, 'offset' => $offset] = self::decodeUint16($data, $offset);

            try {
                $groups[] = NamedGroup::from($groupValue);
            } catch (\ValueError $e) {
                // 忽略未知组，只记录已知组
                continue;
            }
        }

        $extension->setGroups($groups);

        return $extension;
    }
}
