<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Domain\OAuth2;

use Clavia\Domain\Authentication\AuthenticationContext;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\OAuth2\AuthorizationCode;
use Clavia\Domain\OAuth2\AuthorizationCodeId;
use Clavia\Domain\OAuth2\CodeChallenge;
use Clavia\Domain\OAuth2\Refresh;
use Clavia\Domain\OAuth2\RefreshToken;
use Clavia\Domain\OAuth2\RefreshTokenId;
use Clavia\Domain\Shared\Audience;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\ScopeSet;
use ClaviaTest\Support\Fake\SeededRandomSource;
use DateTimeImmutable;
use LogicException;
use PHPUnit\Framework\TestCase;

final class RefreshTokenTest extends TestCase
{
    private const int IDLE = 3600;
    private const int ABSOLUTE = 7200;

    public function testAFamilyStartsFromTheCodeAndIsItsOwnFirstMember(): void
    {
        $code = self::code();

        $token = self::first($code);

        self::assertTrue($token->familyId->equals($token->id));
        self::assertTrue($token->clientId->equals($code->clientId));
        self::assertTrue($token->userId->equals($code->userId));
        self::assertTrue($token->authorizationCodeId?->equals($code->id));
        self::assertSame('https://invoices.example/api/', $token->audience?->value);
        self::assertEquals(new DateTimeImmutable('2026-01-15T11:00:00Z'), $token->expiresAt);
        self::assertEquals(new DateTimeImmutable('2026-01-15T12:00:00Z'), $token->familyExpiresAt);
    }

    public function testASuccessorKeepsEverythingButItsOwnDeadlineWhichNeverPassesTheFamilys(): void
    {
        $first = self::first(self::code());

        $narrowed = ScopeSet::fromString('openid');
        $early = $first->succeededBy(self::id(2), Digest::of('second'), $narrowed, self::at('10:30'), self::IDLE);
        $late = $first->succeededBy(self::id(3), Digest::of('third'), $first->scope, self::at('11:45'), self::IDLE);

        self::assertTrue($early->familyId->equals($first->id));
        self::assertEquals($first->authorizationCodeId, $early->authorizationCodeId);
        self::assertSame('openid', $early->scope->toString());
        self::assertEquals(self::at('11:30'), $early->expiresAt);
        self::assertEquals(self::at('12:00'), $late->expiresAt, 'The family deadline comes before the idle limit.');
        self::assertEquals($first->familyExpiresAt, $late->familyExpiresAt);
    }

    public function testWhatATokenIsToWhoeverPresentsIt(): void
    {
        $token = self::first(self::code());
        $owner = ClientId::fromString('spa');

        self::assertSame(Refresh::Usable, $token->examine($owner, self::at('10:59')));
        $stranger = ClientId::fromString('other');
        self::assertSame(Refresh::IssuedToAnotherClient, $token->examine($stranger, self::at('10:30')));
        self::assertSame(Refresh::Expired, $token->examine($owner, self::at('11:00')));

        $token->spend(self::at('10:30'));
        self::assertEquals(self::at('10:30'), $token->usedAt());
        self::assertSame(Refresh::Replayed, $token->examine($owner, self::at('10:31')));

        $revoked = RefreshToken::reconstitute(
            $token->id,
            $token->digest,
            $token->familyId,
            $token->clientId,
            $token->userId,
            $token->authorizationCodeId,
            $token->scope,
            $token->audience,
            $token->issuedAt,
            $token->expiresAt,
            $token->familyExpiresAt,
            null,
            self::at('10:31'),
        );
        self::assertSame(Refresh::Revoked, $revoked->examine($owner, self::at('10:32')));
    }

    public function testOnlyAUsableTokenCanBeSpent(): void
    {
        $token = self::first(self::code());
        $token->spend(self::at('10:30'));

        $this->expectException(LogicException::class);
        $token->spend(self::at('10:31'));
    }

    private static function first(AuthorizationCode $code): RefreshToken
    {
        return RefreshToken::startFamily(
            self::id(1),
            Digest::of('first'),
            $code,
            ScopeSet::fromString('openid invoices:read'),
            self::at('10:00'),
            self::IDLE,
            self::ABSOLUTE,
        );
    }

    private static function code(): AuthorizationCode
    {
        return AuthorizationCode::issue(
            AuthorizationCodeId::generate(new SeededRandomSource(5)),
            Digest::of('the-code'),
            ClientId::fromString('spa'),
            UserId::generate(new SeededRandomSource(6)),
            'https://app.example/cb',
            ScopeSet::fromString('openid invoices:read'),
            CodeChallenge::fromString(str_repeat('a', 43)),
            Audience::fromString('https://invoices.example/api/'),
            null,
            AuthenticationContext::unknown(),
            self::at('10:00'),
            60,
        );
    }

    private static function id(int $seed): RefreshTokenId
    {
        return RefreshTokenId::generate(new SeededRandomSource($seed));
    }

    private static function at(string $time): DateTimeImmutable
    {
        return new DateTimeImmutable('2026-01-15T' . $time . ':00Z');
    }
}
