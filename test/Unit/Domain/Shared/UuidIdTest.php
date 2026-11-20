<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Domain\Shared;

use Clavia\Domain\Identity\UserId;
use Clavia\Domain\OAuth2\AccessTokenId;
use Clavia\Domain\OAuth2\AuthorizationCodeId;
use Clavia\Domain\Shared\InvalidValue;
use ClaviaTest\Support\Fake\SeededRandomSource;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class UuidIdTest extends TestCase
{
    public function testAGeneratedIdIsAVersion4Uuid(): void
    {
        $random = new SeededRandomSource(1);

        for ($i = 0; $i < 50; $i++) {
            self::assertMatchesRegularExpression(
                '/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/D',
                UserId::generate($random)->value,
            );
        }
    }

    public function testTwoGeneratedIdsDiffer(): void
    {
        $random = new SeededRandomSource(1);

        self::assertFalse(UserId::generate($random)->equals(UserId::generate($random)));
    }

    public function testItSurvivesARoundTripThroughStorage(): void
    {
        $id = UserId::generate(new SeededRandomSource(1));

        self::assertTrue(UserId::fromString($id->toString())->equals($id));
    }

    public function testIdsOfDifferentKindsAreNeverEqual(): void
    {
        $value = '3f2b8c1e-0a4d-4c6b-9e2f-1a2b3c4d5e6f';

        self::assertTrue(AccessTokenId::fromString($value)->equals(AccessTokenId::fromString($value)));
        self::assertFalse(AccessTokenId::fromString($value)->equals(AuthorizationCodeId::fromString($value)));
        self::assertFalse(UserId::fromString($value)->equals(AccessTokenId::fromString($value)));
    }

    #[DataProvider('malformed')]
    public function testAnythingButALowerCaseUuidIsRefused(string $value): void
    {
        $this->expectException(InvalidValue::class);

        UserId::fromString($value);
    }

    /** @return iterable<string, array{string}> */
    public static function malformed(): iterable
    {
        yield 'empty' => [''];
        yield 'upper case' => ['3F2B8C1E-0A4D-4C6B-9E2F-1A2B3C4D5E6F'];
        yield 'no dashes' => ['3f2b8c1e0a4d4c6b9e2f1a2b3c4d5e6f'];
        yield 'braces' => ['{3f2b8c1e-0a4d-4c6b-9e2f-1a2b3c4d5e6f}'];
        yield 'trailing newline' => ["3f2b8c1e-0a4d-4c6b-9e2f-1a2b3c4d5e6f\n"];
        yield 'too short' => ['3f2b8c1e-0a4d-4c6b-9e2f-1a2b3c4d5e6'];
        yield 'not hexadecimal' => ['3f2b8c1e-0a4d-4c6b-9e2f-1a2b3c4d5e6g'];
    }
}
