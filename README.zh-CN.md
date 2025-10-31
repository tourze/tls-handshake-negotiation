# TLS 握手协商

[![构建状态](https://img.shields.io/github/actions/workflow/status/your-org/tls-handshake-negotiation/ci.yml?branch=main)](https://github.com/your-org/tls-handshake-negotiation/actions)
[![代码覆盖率](https://img.shields.io/codecov/c/github/your-org/tls-handshake-negotiation)](https://codecov.io/gh/your-org/tls-handshake-negotiation)
[![PHP Version](https://img.shields.io/badge/php-%3E%3D8.1-blue)](https://php.net/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

[English](README.md) | [中文](README.zh-CN.md)

实现 TLS 握手协商组件的 PHP 库，支持符合 RFC 5246 和 RFC 8446 标准的
TLS 1.2 和 TLS 1.3 协议。

## 目录

- [系统要求](#系统要求)
- [安装](#安装)
- [快速开始](#快速开始)
- [特性](#特性)
- [架构](#架构)
- [高级用法](#高级用法)
- [测试](#测试)
- [安全考虑](#安全考虑)
- [贡献](#贡献)
- [许可证](#许可证)
- [参考资料](#参考资料)

## 系统要求

- PHP 8.1 或更高版本
- OpenSSL 扩展（用于加密操作）

## 安装

```bash
composer require tourze/tls-handshake-negotiation
```

## 快速开始

### 基本加密套件协商

```php
use Tourze\TLSHandshakeNegotiation\Crypto\CipherSuiteNegotiator;
use Tourze\TLSHandshakeNegotiation\Protocol\TLSVersion;

// 为 TLS 1.3 创建协商器
$negotiator = new CipherSuiteNegotiator(TLSVersion::TLS_1_3);

// 获取支持的加密套件
$supportedSuites = $negotiator->getSupportedCipherSuites();

// 与客户端协商加密套件
$clientSuites = [0x1301, 0x1302]; // TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384
$selectedSuite = $negotiator->negotiate($clientSuites);
```

### 握手配置

```php
use Tourze\TLSHandshakeNegotiation\Config\HandshakeConfig;

$config = new HandshakeConfig();
$config->setServerMode(true);
$config->setSupportedVersions(['TLS 1.2', 'TLS 1.3']);
$config->setCertificatePath('/path/to/certificate.pem');
$config->setPrivateKeyPath('/path/to/private.key');
```

## 特性

- **加密套件协商**: 处理加密算法和协议的选择
- **扩展协商**: 支持 TLS 扩展，包括：
  - 早期数据扩展（TLS 1.3）
  - 密钥共享扩展（TLS 1.3）
  - 预共享密钥扩展（TLS 1.3）
  - 重新协商信息扩展
  - 支持的组扩展
- **版本协商**: 管理 TLS 版本选择和降级保护
- **PSK 管理**: 预共享密钥处理和会话管理
- **证书处理**: 客户端和服务器证书验证
- **密钥导出**: 主密钥导出和验证数据生成

## 架构

包按以下关键组件组织：

- **Config**: 握手参数的配置管理
- **Crypto**: 加密套件协商和证书处理
- **Extension**: TLS 扩展实现
- **Handshake**: 握手阶段管理
- **KeyDerivation**: 密钥导出和验证
- **Protocol**: TLS 版本处理
- **Session**: PSK 会话管理

## 高级用法

### 扩展处理

```php
use Tourze\TLSHandshakeNegotiation\Extension\KeyShareExtension;
use Tourze\TLSHandshakeNegotiation\Extension\NamedGroup;

// 创建密钥共享扩展
$keyShare = new KeyShareExtension(false); // 客户端模式
$keyShare->addKeyShareEntry(NamedGroup::SECP256R1, 'public_key_data');

// 编码扩展数据
$encodedData = $keyShare->encode();

// 解码扩展数据
$decodedExtension = KeyShareExtension::decode($encodedData);
```

### PSK 会话管理

```php
use Tourze\TLSHandshakeNegotiation\Session\TLS13PSKSession;
use Tourze\TLSHandshakeNegotiation\Session\TLS13PSKMode;

$pskSession = new TLS13PSKSession(
    'session_id',
    'psk_key',
    'cipher_suite',
    TLS13PSKMode::PSK_DHE_KE
);

// 检查会话是否有效
if ($pskSession->isValid()) {
    // 使用 PSK 会话
    $pskKey = $pskSession->getPskKey();
}
```

### 自定义扩展实现

```php
use Tourze\TLSHandshakeNegotiation\Extension\AbstractExtension;
use Tourze\TLSHandshakeNegotiation\Extension\ExtensionType;

class CustomExtension extends AbstractExtension
{
    public function getType(): int
    {
        return ExtensionType::CUSTOM;
    }

    public function encode(): string
    {
        // 实现编码逻辑
        return $this->encodeData();
    }

    public static function decode(string $data, bool $isServerFormat = false): static
    {
        // 实现解码逻辑
        return new static();
    }
}
```

### 依赖

- `tourze/enum-extra`: 增强的枚举工具
- `tourze/tls-common`: 通用 TLS 数据结构
- `tourze/tls-crypto-keyexchange`: 密钥交换算法
- `tourze/tls-handshake-messages`: 握手消息定义

## 测试

运行测试套件：

```bash
composer test
```

运行 PHPStan 分析：

```bash
composer analyze
```

## 安全考虑

- 所有实现严格遵循 RFC 规范
- 优先考虑安全性而非性能
- 检测弱加密套件并发出警告
- 对握手失败进行适当的错误处理
- 优先使用不可变对象以避免共享状态问题

## 贡献

请阅读 [CONTRIBUTING.md](CONTRIBUTING.md) 了解贡献指南。

## 许可证

本项目基于 MIT 许可证 - 详情请参见 [LICENSE](LICENSE) 文件。

## 参考资料

- [RFC 5246: 传输层安全协议 (TLS) 版本 1.2](https://tools.ietf.org/html/rfc5246)
- [RFC 8446: 传输层安全协议 (TLS) 版本 1.3](https://tools.ietf.org/html/rfc8446)
- [RFC 5746: 传输层安全 (TLS) 重新协商指示扩展](https://tools.ietf.org/html/rfc5746)