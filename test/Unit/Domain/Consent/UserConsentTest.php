<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Domain\Consent;

use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Consent\UserConsent;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Shared\ScopeSet;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

final class UserConsentTest extends TestCase
{
    public function testItCoversWhatWasAgreedAndLess(): void
    {
        $consent = self::given('openid email');

        self::assertTrue($consent->covers(ScopeSet::fromString('openid email')));
        self::assertTrue($consent->covers(ScopeSet::fromString('openid')));
        self::assertTrue($consent->covers(ScopeSet::empty()));
        self::assertFalse($consent->covers(ScopeSet::fromString('openid profile')));
    }

    public function testWideningIsTheUnionAndDatesTheChange(): void
    {
        $later = new DateTimeImmutable('2026-01-15T11:00:00Z');

        $widened = self::given('openid')->widenedBy(ScopeSet::fromString('profile'), $later);

        self::assertTrue($widened->covers(ScopeSet::fromString('openid profile')));
        self::assertEquals(new DateTimeImmutable('2026-01-15T10:00:00Z'), $widened->grantedAt);
        self::assertEquals($later, $widened->updatedAt);
    }

    public function testWideningByWhatIsCoveredChangesNothing(): void
    {
        $consent = self::given('openid email');

        self::assertSame(
            $consent,
            $consent->widenedBy(ScopeSet::fromString('email'), new DateTimeImmutable('2026-01-15T11:00:00Z')),
        );
    }

    private static function given(string $scope): UserConsent
    {
        return UserConsent::give(
            UserId::fromString('00000000-0000-4000-8000-000000000001'),
            ClientId::fromString('tpc_partner'),
            null,
            ScopeSet::fromString($scope),
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
        );
    }
}
