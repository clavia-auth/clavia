<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Domain\Shared;

use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\Scope;
use Clavia\Domain\Shared\ScopeSet;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class ScopeSetTest extends TestCase
{
    public function testItParsesTheSpaceDelimitedWireForm(): void
    {
        $scopes = ScopeSet::fromString('openid profile read:users');

        self::assertSame(['openid', 'profile', 'read:users'], $scopes->toList());
        self::assertSame('openid profile read:users', $scopes->toString());
        self::assertCount(3, $scopes);
    }

    public function testRepetitionMeansNothing(): void
    {
        self::assertSame('openid email', ScopeSet::fromString('openid email openid')->toString());
    }

    public function testStraySpacesAreTolerated(): void
    {
        self::assertSame('openid email', ScopeSet::fromString('  openid   email ')->toString());
    }

    public function testAnEmptyParameterIsAnEmptySet(): void
    {
        self::assertTrue(ScopeSet::fromString('')->isEmpty());
        self::assertTrue(ScopeSet::fromString('   ')->isEmpty());
        self::assertSame('', ScopeSet::empty()->toString());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function malformedScopes(): iterable
    {
        yield 'a tab as separator' => ["openid\tprofile"];
        yield 'a newline as separator' => ["openid\nprofile"];
        yield 'a double quote' => ['read:"users"'];
        yield 'a backslash' => ['read\\users'];
        yield 'a non-ASCII character' => ['lecture:données'];
        yield 'a control character' => ["openid\x00"];
    }

    #[DataProvider('malformedScopes')]
    public function testACharacterRfc6749ForbidsIsRefusedNotGuessedAround(string $scope): void
    {
        $this->expectException(InvalidValue::class);

        ScopeSet::fromString($scope);
    }

    public function testASingleScopeCannotBeEmptyOrHoldASpace(): void
    {
        $refused = 0;
        foreach (['', 'two words'] as $value) {
            try {
                Scope::fromString($value);
            } catch (InvalidValue) {
                $refused++;
            }
        }

        self::assertSame(2, $refused);
    }

    public function testOrderDoesNotMatterForEquality(): void
    {
        self::assertTrue(ScopeSet::fromString('a b c')->equals(ScopeSet::fromString('c a b')));
        self::assertFalse(ScopeSet::fromString('a b')->equals(ScopeSet::fromString('a b c')));
        self::assertFalse(ScopeSet::fromString('a b c')->equals(ScopeSet::fromString('a b')));
    }

    public function testScopesAreCaseSensitive(): void
    {
        self::assertFalse(ScopeSet::fromString('OpenID')->contains('openid'));
        self::assertCount(2, ScopeSet::fromString('openid OpenID'));
    }

    public function testNarrowingKeepsOnlyWhatBothSidesHold(): void
    {
        $requested = ScopeSet::fromString('openid read:users delete:users');
        $allowed = ScopeSet::fromString('read:users openid write:users');

        self::assertSame('openid read:users', $requested->intersect($allowed)->toString());
        self::assertSame('delete:users', $requested->without($allowed)->toString());
    }

    public function testNarrowingNeverWidens(): void
    {
        $requested = ScopeSet::fromString('openid');
        $allowed = ScopeSet::fromString('openid read:users');

        self::assertTrue($requested->intersect($allowed)->isSubsetOf($requested));
        self::assertTrue($requested->intersect(ScopeSet::empty())->isEmpty());
    }

    public function testSubsetIsHowAnOverAskIsDetected(): void
    {
        $granted = ScopeSet::fromString('openid profile');

        self::assertTrue(ScopeSet::fromString('openid')->isSubsetOf($granted));
        self::assertTrue(ScopeSet::empty()->isSubsetOf($granted));
        self::assertTrue($granted->isSubsetOf($granted));
        self::assertFalse(ScopeSet::fromString('openid email')->isSubsetOf($granted));
    }

    public function testUnionAddsWithoutDuplicating(): void
    {
        $union = ScopeSet::fromString('openid profile')->union(ScopeSet::fromString('profile email'));

        self::assertSame('openid profile email', $union->toString());
    }

    public function testItIteratesOverScopes(): void
    {
        $values = [];
        foreach (ScopeSet::fromString('a b') as $scope) {
            $values[] = $scope->value;
        }

        self::assertSame(['a', 'b'], $values);
        self::assertTrue(ScopeSet::of(Scope::fromString('a'))->contains(Scope::fromString('a')));
    }

    public function testNumericLookingScopesStayStrings(): void
    {
        $scopes = ScopeSet::fromString('10 2 openid');

        self::assertSame(['10', '2', 'openid'], $scopes->toList());
        self::assertTrue($scopes->contains('10'));
    }
}
