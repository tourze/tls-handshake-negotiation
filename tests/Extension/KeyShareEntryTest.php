<?php

declare(strict_types=1);

namespace Tourze\TLSHandshakeNegotiation\Extension;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;

/**
 * @internal
 */
#[CoversClass(KeyShareEntry::class)]
final class KeyShareEntryTest extends TestCase
{
    public function testGetSetGroup(): void
    {
        $entry = new KeyShareEntry();
        $entry->setGroup(0x0017);

        $this->assertSame(0x0017, $entry->getGroup());
    }

    public function testGetSetKeyExchange(): void
    {
        $entry = new KeyShareEntry();
        $keyExchange = 'test_key_exchange_data';
        $entry->setKeyExchange($keyExchange);

        $this->assertSame($keyExchange, $entry->getKeyExchange());
    }

    public function testSetMultipleProperties(): void
    {
        $group = 0x001D;
        $keyExchange = 'key_data';

        $entry = new KeyShareEntry();
        $entry->setGroup($group);
        $entry->setKeyExchange($keyExchange);

        $this->assertSame($group, $entry->getGroup());
        $this->assertSame($keyExchange, $entry->getKeyExchange());
    }
}
