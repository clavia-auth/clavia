<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Domain\Oidc;

use Clavia\Domain\Oidc\Nonce;
use Clavia\Domain\Shared\InvalidValue;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class NonceTest extends TestCase
{
    public function testAnyPrintableTextUpTo512BytesIsANonce(): void
    {
        self::assertSame('n-0S6_WzA2Mj', Nonce::fromString('n-0S6_WzA2Mj')->value);
        self::assertSame('with spaces/and+symbols=', Nonce::fromString('with spaces/and+symbols=')->value);
        self::assertSame('nonce-é-ü', Nonce::fromString('nonce-é-ü')->value);
        self::assertSame(512, strlen(Nonce::fromString(str_repeat('n', 512))->value));
    }

    public function testNoncesAreComparedExactly(): void
    {
        self::assertTrue(Nonce::fromString('abc')->equals(Nonce::fromString('abc')));
        self::assertFalse(Nonce::fromString('abc')->equals(Nonce::fromString('ABC')));
    }

    #[DataProvider('notANonce')]
    public function testAnythingElseIsRefused(string $value): void
    {
        $this->expectException(InvalidValue::class);

        Nonce::fromString($value);
    }

    /** @return iterable<string, array{string}> */
    public static function notANonce(): iterable
    {
        yield 'empty' => [''];
        yield 'longer than 512 bytes' => [str_repeat('n', 513)];
        yield 'a line break' => ["one\ntwo"];
        yield 'a NUL byte' => ["nonce\0"];
        yield 'DEL' => ["nonce\x7F"];
        yield 'not UTF-8' => ["nonce\xFF"];
    }
}
