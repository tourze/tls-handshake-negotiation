# TLS Handshake Negotiation

[![Build Status](https://img.shields.io/github/actions/workflow/status/your-org/tls-handshake-negotiation/ci.yml?branch=main)](https://github.com/your-org/tls-handshake-negotiation/actions)
[![Code Coverage](https://img.shields.io/codecov/c/github/your-org/tls-handshake-negotiation)](https://codecov.io/gh/your-org/tls-handshake-negotiation)
[![PHP Version](https://img.shields.io/badge/php-%3E%3D8.1-blue)](https://php.net/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

[English](README.md) | [中文](README.zh-CN.md)

A PHP library implementing TLS handshake negotiation components with support for 
TLS 1.2 and TLS 1.3 protocols per RFC 5246 and RFC 8446.

## Table of Contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Features](#features)
- [Architecture](#architecture)
- [Advanced Usage](#advanced-usage)
- [Testing](#testing)
- [Security Considerations](#security-considerations)
- [Contributing](#contributing)
- [License](#license)
- [References](#references)

## Requirements

- PHP 8.1 or higher
- OpenSSL extension (for cryptographic operations)

## Installation

```bash
composer require tourze/tls-handshake-negotiation
```

## Quick Start

### Basic Cipher Suite Negotiation

```php
use Tourze\TLSHandshakeNegotiation\Crypto\CipherSuiteNegotiator;
use Tourze\TLSHandshakeNegotiation\Protocol\TLSVersion;

// Create negotiator for TLS 1.3
$negotiator = new CipherSuiteNegotiator(TLSVersion::TLS_1_3);

// Get supported cipher suites
$supportedSuites = $negotiator->getSupportedCipherSuites();

// Negotiate cipher suite with client
$clientSuites = [0x1301, 0x1302]; // TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384
$selectedSuite = $negotiator->negotiate($clientSuites);
```

### Handshake Configuration

```php
use Tourze\TLSHandshakeNegotiation\Config\HandshakeConfig;

$config = new HandshakeConfig();
$config->setServerMode(true);
$config->setSupportedVersions(['TLS 1.2', 'TLS 1.3']);
$config->setCertificatePath('/path/to/certificate.pem');
$config->setPrivateKeyPath('/path/to/private.key');
```

## Features

- **Cipher Suite Negotiation**: Handles selection of encryption algorithms and protocols
- **Extension Negotiation**: Supports TLS extensions including:
  - Early Data Extension (TLS 1.3)
  - Key Share Extension (TLS 1.3)
  - Pre-Shared Key Extension (TLS 1.3)
  - Renegotiation Info Extension
  - Supported Groups Extension
- **Version Negotiation**: Manages TLS version selection and downgrade protection
- **PSK Management**: Pre-shared key handling and session management
- **Certificate Handling**: Client and server certificate verification
- **Key Derivation**: Master secret derivation and verify data generation

## Architecture

The package is organized into several key components:

- **Config**: Configuration management for handshake parameters
- **Crypto**: Cipher suite negotiation and certificate handling
- **Extension**: TLS extension implementations
- **Handshake**: Handshake stage management
- **KeyDerivation**: Key derivation and verification
- **Protocol**: TLS version handling
- **Session**: PSK session management

## Advanced Usage

### Extension Handling

```php
use Tourze\TLSHandshakeNegotiation\Extension\KeyShareExtension;
use Tourze\TLSHandshakeNegotiation\Extension\NamedGroup;

// Create key share extension
$keyShare = new KeyShareExtension(false); // Client mode
$keyShare->addKeyShareEntry(NamedGroup::SECP256R1, 'public_key_data');

// Encode extension data
$encodedData = $keyShare->encode();

// Decode extension data
$decodedExtension = KeyShareExtension::decode($encodedData);
```

### PSK Session Management

```php
use Tourze\TLSHandshakeNegotiation\Session\TLS13PSKSession;
use Tourze\TLSHandshakeNegotiation\Session\TLS13PSKMode;

$pskSession = new TLS13PSKSession(
    'session_id',
    'psk_key',
    'cipher_suite',
    TLS13PSKMode::PSK_DHE_KE
);

// Check if session is valid
if ($pskSession->isValid()) {
    // Use PSK session
    $pskKey = $pskSession->getPskKey();
}
```

### Custom Extension Implementation

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
        // Implement encoding logic
        return $this->encodeData();
    }

    public static function decode(string $data, bool $isServerFormat = false): static
    {
        // Implement decoding logic
        return new static();
    }
}
```

### Dependencies

- `tourze/enum-extra`: Enhanced enum utilities
- `tourze/tls-common`: Common TLS data structures
- `tourze/tls-crypto-keyexchange`: Key exchange algorithms
- `tourze/tls-handshake-messages`: Handshake message definitions

## Testing

Run the test suite:

```bash
composer test
```

Run PHPStan analysis:

```bash
composer analyze
```

## Security Considerations

- All implementations follow RFC specifications strictly
- Security is prioritized over performance
- Weak cipher suites are detected and warnings are issued
- Proper error handling for handshake failures
- Immutable objects are preferred to avoid shared state issues

## Contributing

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## References

- [RFC 5246: The Transport Layer Security (TLS) Protocol Version 1.2](https://tools.ietf.org/html/rfc5246)
- [RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3](https://tools.ietf.org/html/rfc8446)
- [RFC 5746: Transport Layer Security (TLS) Renegotiation Indication Extension](https://tools.ietf.org/html/rfc5746)
