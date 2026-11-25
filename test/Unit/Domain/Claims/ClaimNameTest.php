<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Domain\Claims;

use Clavia\Domain\Claims\ClaimName;
use Clavia\Domain\Shared\InvalidValue;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class ClaimNameTest extends TestCase
{
    /** @return iterable<string, array{string}> */
    public static function accepted(): iterable
    {
        yield 'a plain name' => ['plan'];
        yield 'dots, dashes and underscores' => ['org.example_tenant-id'];
        yield 'sixty-four characters' => [str_repeat('a', 64)];
        yield 'an https URI' => ['https://example.com/claims/plan'];
    }

    #[DataProvider('accepted')]
    public function testAnUnreservedNameIsKept(string $name): void
    {
        self::assertSame($name, ClaimName::fromString($name, onAnApi: false)->value);
    }

    /** @return iterable<string, array{string}> */
    public static function malformed(): iterable
    {
        yield 'empty' => [''];
        yield 'sixty-five characters' => [str_repeat('a', 65)];
        yield 'a space' => ['the plan'];
        yield 'an http URI' => ['http://example.com/plan'];
        yield 'a fragment' => ['https://example.com/claims#plan'];
        yield 'a URI over 255' => ['https://example.com/' . str_repeat('a', 240)];
    }

    #[DataProvider('malformed')]
    public function testAMalformedNameIsRefused(string $name): void
    {
        $this->expectException(InvalidValue::class);

        ClaimName::fromString($name, onAnApi: true);
    }

    /** @return iterable<string, array{string}> */
    public static function reserved(): iterable
    {
        foreach (
            ['sub', 'iss', 'aud', 'exp', 'jti', 'acr', 'amr', 'auth_time', 'email', 'email_verified', 'name',
            'scope', 'client_id', 'cnf', 'sid', 'act', 'groups', 'entitlements', 'active', 'username',
            'token_type', 'permissions', 'authorization_details'] as $name
        ) {
            yield $name => [$name];
        }
    }

    #[DataProvider('reserved')]
    public function testAReservedNameIsRefusedWherever(string $name): void
    {
        $this->expectException(InvalidValue::class);

        ClaimName::fromString($name, onAnApi: true);
    }

    public function testRolesIsAllowedOnAnApiOnly(): void
    {
        self::assertSame('roles', ClaimName::fromString('roles', onAnApi: true)->value);

        $this->expectException(InvalidValue::class);
        ClaimName::fromString('roles', onAnApi: false);
    }

    public function testStorageKeepsAReservedNameSoTheMappingStillLoads(): void
    {
        self::assertTrue(ClaimName::fromStorage('sub')->isReserved());
        self::assertFalse(ClaimName::fromStorage('plan')->isReserved());
    }

    public function testTheReservedListHoldsEachNameOnce(): void
    {
        self::assertSame(array_values(array_unique(ClaimName::RESERVED)), ClaimName::RESERVED);
    }
}
