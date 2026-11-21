<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Domain\OAuth2;

use Clavia\Domain\OAuth2\ErrorCode;
use Clavia\Domain\OAuth2\MaxAge;
use Clavia\Domain\OAuth2\OAuth2Error;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class MaxAgeTest extends TestCase
{
    public function testAbsentIsNoLimit(): void
    {
        self::assertNull(MaxAge::fromParameter(null));
    }

    public function testASignInOlderThanTheLimitIsTooOldInWholeSeconds(): void
    {
        $now = new DateTimeImmutable('2026-01-15T10:00:00.900Z');
        $maxAge = MaxAge::fromParameter('60');
        self::assertNotNull($maxAge);

        self::assertFalse($maxAge->isExceededBy(new DateTimeImmutable('2026-01-15T09:59:00.999Z'), $now));
        self::assertTrue($maxAge->isExceededBy(new DateTimeImmutable('2026-01-15T09:58:59Z'), $now));
        self::assertTrue($maxAge->isExceededBy(null, $now), 'An unknown time is not recent.');
    }

    public function testZeroAsksForASignInNow(): void
    {
        $now = new DateTimeImmutable('2026-01-15T10:00:00Z');
        $zero = MaxAge::fromParameter('0');
        self::assertNotNull($zero);

        self::assertTrue($zero->isZero());
        self::assertTrue($zero->isExceededBy($now, $now));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function notSeconds(): iterable
    {
        yield 'negative' => ['-1'];
        yield 'a word' => ['soon'];
        yield 'a fraction' => ['1.5'];
        yield 'a leading zero' => ['060'];
        yield 'a plus sign' => ['+60'];
        yield 'too many digits' => ['12345678901'];
    }

    #[DataProvider('notSeconds')]
    public function testAnythingButWholeSecondsIsAnInvalidRequest(string $parameter): void
    {
        try {
            MaxAge::fromParameter($parameter);
            self::fail('Accepted: ' . $parameter);
        } catch (OAuth2Error $error) {
            self::assertSame(ErrorCode::InvalidRequest, $error->error);
        }
    }
}
