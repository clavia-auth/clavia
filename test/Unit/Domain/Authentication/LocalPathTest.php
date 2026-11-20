<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Domain\Authentication;

use Clavia\Domain\Authentication\LocalPath;
use Clavia\Domain\Shared\InvalidValue;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class LocalPathTest extends TestCase
{
    #[DataProvider('local')]
    public function testAPathOnThisServerIsKeptAsItIs(string $value): void
    {
        self::assertSame($value, LocalPath::fromString($value)->value);
        self::assertSame($value, LocalPath::orDefault($value)->value);
    }

    /** @return iterable<string, array{string}> */
    public static function local(): iterable
    {
        yield 'the root' => ['/'];
        yield 'an authorization request' => ['/oauth2/authorize?response_type=code&client_id=spa&state=a%20b'];
        yield 'a percent-encoded slash' => ['/%2F%2Fevil.example'];
        yield 'a fragment' => ['/auth/login#top'];
    }

    /**
     * Each of these, written into a `Location`, would send the browser somewhere else —
     * or split the header.
     */
    #[DataProvider('hostile')]
    public function testAnythingThatCouldLeaveThisServerIsRefused(string $value): void
    {
        self::assertSame('/auth/login', LocalPath::orDefault($value)->value);

        $this->expectException(InvalidValue::class);

        LocalPath::fromString($value);
    }

    /** @return iterable<string, array{string}> */
    public static function hostile(): iterable
    {
        yield 'an absolute URL' => ['https://evil.example/steal'];
        yield 'a protocol-relative reference' => ['//evil.example'];
        yield 'a backslash variant' => ['/\\evil.example'];
        yield 'two backslashes' => ['\\\\evil.example'];
        yield 'a script URL' => ['javascript:alert(1)'];
        yield 'a relative path' => ['auth/login'];
        yield 'a header split' => ["/ok\r\nLocation: https://evil.example"];
        yield 'a bare line feed' => ["/ok\nx"];
        yield 'a tab' => ["/\t/evil.example"];
        yield 'a NUL byte' => ["/ok\0"];
        yield 'a DEL character' => ["/ok\x7F"];
    }

    public function testNothingFallsBackToTheDefault(): void
    {
        self::assertSame('/auth/login', LocalPath::orDefault(null)->value);
        self::assertSame('/auth/login', LocalPath::orDefault('')->value);
        self::assertSame('/elsewhere', LocalPath::orDefault('https://evil.example', '/elsewhere')->value);
    }
}
