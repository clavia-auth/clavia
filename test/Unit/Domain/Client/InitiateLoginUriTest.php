<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Domain\Client;

use Clavia\Domain\Client\InitiateLoginUri;
use Clavia\Domain\Shared\InvalidValue;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * A client's sign-in start address (OpenID Connect Dynamic Client Registration 1.0 §2, Core 1.0 §4).
 */
final class InitiateLoginUriTest extends TestCase
{
    public function testItIsKeptByteForByte(): void
    {
        self::assertSame(
            'https://App.example/dashboard/auth/sign-in',
            InitiateLoginUri::fromString('https://App.example/dashboard/auth/sign-in')->uri->value,
        );
    }

    #[DataProvider('refused')]
    public function testOnlyAnHttpsUrlWithoutAFragmentIsTaken(string $value): void
    {
        $this->expectException(InvalidValue::class);

        InitiateLoginUri::fromString($value);
    }

    /** @return iterable<string, array{string}> */
    public static function refused(): iterable
    {
        // Registration §2: "The URL MUST use the https scheme".
        yield 'http' => ['http://app.example/sign-in'];
        yield 'another scheme' => ['javascript://app.example/%0aalert(1)'];
        // The `iss` appended to it would be swallowed.
        yield 'a fragment' => ['https://app.example/sign-in#start'];
        yield 'relative' => ['/sign-in'];
        yield 'empty' => [''];
    }

    /** Core §4: `iss` is required; it is appended, the registered address left as it is. */
    public function testTheIssuerIsAppendedToTheRegisteredAddress(): void
    {
        self::assertSame(
            'https://app.example/sign-in?iss=https%3A%2F%2Fauth.example.com',
            InitiateLoginUri::fromString('https://app.example/sign-in')->forIssuer('https://auth.example.com'),
        );
        self::assertSame(
            'https://app.example/sign-in?tenant=a%20b&iss=https%3A%2F%2Fauth.example.com',
            InitiateLoginUri::fromString('https://app.example/sign-in?tenant=a%20b')
                ->forIssuer('https://auth.example.com'),
        );
    }
}
