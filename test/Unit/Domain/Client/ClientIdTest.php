<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Domain\Client;

use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\SecretGenerator;
use ClaviaTest\Support\Fake\SeededRandomSource;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class ClientIdTest extends TestCase
{
    public function testAGeneratedIdIs32AlphanumericCharacters(): void
    {
        $secrets = new SecretGenerator(new SeededRandomSource(1));

        $first = ClientId::generate($secrets);
        $second = ClientId::generate($secrets);

        self::assertMatchesRegularExpression('/^[A-Za-z0-9]{32}$/D', $first->value);
        self::assertFalse($first->equals($second));
    }

    #[DataProvider('accepted')]
    public function testVisibleAsciiIsAccepted(string $value): void
    {
        self::assertSame($value, ClientId::fromString($value)->value);
    }

    /** @return iterable<string, array{string}> */
    public static function accepted(): iterable
    {
        yield 'one character' => ['a'];
        yield 'a numeric string' => ['12345'];
        yield 'punctuation' => ['my-app_v2.prod~!$'];
        yield 'the longest allowed' => [str_repeat('a', 64)];
    }

    #[DataProvider('refused')]
    public function testAnythingElseIsRefused(string $value): void
    {
        $this->expectException(InvalidValue::class);

        ClientId::fromString($value);
    }

    /** @return iterable<string, array{string}> */
    public static function refused(): iterable
    {
        yield 'empty' => [''];
        yield 'too long' => [str_repeat('a', 65)];
        yield 'a space' => ['my app'];
        // It could not be told from its secret in HTTP Basic credentials (RFC 7617 §2).
        yield 'a colon' => ['my:app'];
        yield 'a control character' => ["app\x00"];
        yield 'a trailing newline' => ["app\n"];
        yield 'non-ASCII' => ['café'];
    }

    public function testEqualityIsExact(): void
    {
        self::assertTrue(ClientId::fromString('spa')->equals(ClientId::fromString('spa')));
        self::assertFalse(ClientId::fromString('spa')->equals(ClientId::fromString('SPA')));
    }
}
