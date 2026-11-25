<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Domain\Provisioning;

use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Provisioning\ProvisioningToken;
use Clavia\Domain\Provisioning\ProvisioningTokenId;
use Clavia\Domain\Provisioning\ProvisioningTokenState;
use Clavia\Domain\Provisioning\SubjectAttribute;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\InvalidValue;
use ClaviaTest\Support\Fake\SeededRandomSource;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** docs/design/scim-provisioning.md §2, §10 question 4. */
final class ProvisioningTokenTest extends TestCase
{
    private const string NOW = '2026-01-15T10:00:00Z';

    public function testAYearByDefaultAndActiveUntilThen(): void
    {
        $token = self::token();

        self::assertEquals(new DateTimeImmutable('2027-01-15T10:00:00Z'), $token->expiresAt);
        self::assertSame(ProvisioningTokenState::Active, $token->stateAt(new DateTimeImmutable(self::NOW)));
        self::assertTrue($token->isUsableAt(new DateTimeImmutable('2027-01-15T09:59:59Z')));
        self::assertSame(ProvisioningTokenState::Expired, $token->stateAt($token->expiresAt), 'Not at its expiry.');
        self::assertFalse($token->isUsableAt($token->expiresAt));
    }

    /** @return iterable<string, array{int}> */
    public static function lifetimesOutOfBounds(): iterable
    {
        yield 'under a day' => [86_399];
        yield 'over two years' => [63_072_001];
    }

    #[DataProvider('lifetimesOutOfBounds')]
    public function testALifetimeIsADayToTwoYears(int $seconds): void
    {
        $this->expectException(InvalidValue::class);

        self::token($seconds);
    }

    public function testTheBoundsThemselvesAreAccepted(): void
    {
        self::assertTrue(self::token(86_400)->isUsableAt(new DateTimeImmutable(self::NOW)));
        self::assertTrue(self::token(63_072_000)->isUsableAt(new DateTimeImmutable(self::NOW)));
    }

    /** @return iterable<string, array{string}> */
    public static function badDescriptions(): iterable
    {
        yield 'empty' => [''];
        yield 'too long' => [str_repeat('a', 121)];
        yield 'two lines' => ["Entra\nOkta"];
    }

    #[DataProvider('badDescriptions')]
    public function testADescriptionIsOneShortLine(string $description): void
    {
        $this->expectException(InvalidValue::class);

        self::token(description: $description);
    }

    public function testItIsFlaggedWithinThirtyDaysOfItsExpiry(): void
    {
        $token = self::token();

        self::assertFalse($token->isExpiringSoonAt(new DateTimeImmutable('2026-12-16T09:59:59Z')));
        self::assertTrue($token->isExpiringSoonAt(new DateTimeImmutable('2026-12-16T10:00:00Z')), 'Thirty days left.');
        self::assertFalse($token->isExpiringSoonAt($token->expiresAt), 'An expired token is no longer flagged.');
        self::assertFalse(
            $token->revoke(new DateTimeImmutable('2026-12-20T10:00:00Z'))
                ->isExpiringSoonAt(new DateTimeImmutable('2026-12-20T10:00:00Z')),
            'Nor a revoked one.',
        );
    }

    public function testARevocationStopsItAndKeepsItsFirstInstant(): void
    {
        $first = new DateTimeImmutable('2026-02-01T10:00:00Z');
        $revoked = self::token()->revoke($first)->revoke(new DateTimeImmutable('2026-03-01T10:00:00Z'));

        self::assertEquals($first, $revoked->revokedAt);
        $later = new DateTimeImmutable('2026-02-02T10:00:00Z');
        self::assertSame(ProvisioningTokenState::Revoked, $revoked->stateAt($later));
        self::assertSame(ProvisioningTokenState::Revoked, $revoked->stateAt($revoked->expiresAt), 'Revoked first.');
    }

    public function testItKeepsItsOptions(): void
    {
        $token = ProvisioningToken::issue(
            ProvisioningTokenId::generate(new SeededRandomSource(1)),
            Digest::of('secret'),
            ConnectionName::fromString('acme'),
            'Okta',
            new DateTimeImmutable(self::NOW),
            ProvisioningToken::DEFAULT_LIFETIME_SECONDS,
            SubjectAttribute::UserName,
            true,
            true,
        );

        self::assertSame('acme', $token->connection->value);
        self::assertSame(SubjectAttribute::UserName, $token->subjectAttribute);
        self::assertTrue($token->addressesTrusted);
        self::assertTrue($token->deleteDeactivates);
    }

    private static function token(
        int $lifetime = ProvisioningToken::DEFAULT_LIFETIME_SECONDS,
        string $description = 'Entra ID',
    ): ProvisioningToken {
        return ProvisioningToken::issue(
            ProvisioningTokenId::generate(new SeededRandomSource(1)),
            Digest::of('secret'),
            ConnectionName::fromString('password'),
            $description,
            new DateTimeImmutable(self::NOW),
            $lifetime,
            SubjectAttribute::ExternalId,
            false,
            false,
        );
    }
}
