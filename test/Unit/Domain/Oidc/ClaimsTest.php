<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Domain\Oidc;

use Clavia\Domain\Authentication\AuthenticationContext;
use Clavia\Domain\Authentication\AuthenticationMethod;
use Clavia\Domain\Authentication\Session;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Identity\Profile;
use Clavia\Domain\Identity\User;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Oidc\IdentityClaims;
use Clavia\Domain\Oidc\IdTokenClaims;
use Clavia\Domain\Oidc\Nonce;
use Clavia\Domain\Shared\ScopeSet;
use ClaviaTest\Support\Fake\SeededRandomSource;
use DateTimeImmutable;
use PHPUnit\Framework\TestCase;

final class ClaimsTest extends TestCase
{
    private const string ISSUER = 'https://auth.clavia.test';

    private User $user;

    #[\Override]
    protected function setUp(): void
    {
        $this->user = User::register(
            UserId::generate(new SeededRandomSource(7)),
            'ada@example.com',
            null,
            new DateTimeImmutable('2026-01-01T00:00:00Z'),
        );
        $this->user->changeProfile(
            Profile::of(name: 'Ada Lovelace', givenName: 'Ada', picture: 'https://example.com/ada.png'),
            new DateTimeImmutable('2026-01-02T00:00:00Z'),
        );
    }

    // ── What a scope releases ───────────────────────────────────────────────────

    public function testTheSubjectIsAllThatOpenidAloneReleases(): void
    {
        self::assertSame(['sub' => $this->user->id->value], IdentityClaims::of($this->user, $this->scope('openid')));
    }

    public function testProfileReleasesTheClaimsThatAreSetAndWhenTheyChanged(): void
    {
        self::assertSame(
            [
                'sub' => $this->user->id->value,
                'name' => 'Ada Lovelace',
                'given_name' => 'Ada',
                'picture' => 'https://example.com/ada.png',
                'updated_at' => new DateTimeImmutable('2026-01-02T00:00:00Z')->getTimestamp(),
            ],
            IdentityClaims::of($this->user, $this->scope('openid profile')),
        );
    }

    public function testEmailReleasesTheAddressAndWhetherItWasVerified(): void
    {
        self::assertSame(
            ['sub' => $this->user->id->value, 'email' => 'ada@example.com', 'email_verified' => false],
            IdentityClaims::of($this->user, $this->scope('openid email')),
        );
    }

    // ── The ID token ────────────────────────────────────────────────────────────

    public function testAnIdTokenSaysWhoToWhomWhenAndHow(): void
    {
        $session = Session::establish(
            $this->user->id,
            [AuthenticationMethod::Password],
            'sid-value',
            new DateTimeImmutable('2026-01-15T09:30:00Z'),
            86_400,
        );

        $claims = IdTokenClaims::issue(
            self::ISSUER,
            $this->user,
            ClientId::fromString('spa'),
            $this->scope('openid email'),
            Nonce::fromString('n-0S6_WzA2Mj'),
            AuthenticationContext::fromSession($session),
            'the-at-hash',
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
            300,
        )->toArray();

        $issuedAt = new DateTimeImmutable('2026-01-15T10:00:00Z')->getTimestamp();
        self::assertSame(
            [
                'iss' => self::ISSUER,
                'sub' => $this->user->id->value,
                'aud' => 'spa',
                'exp' => $issuedAt + 300,
                'iat' => $issuedAt,
                'auth_time' => new DateTimeImmutable('2026-01-15T09:30:00Z')->getTimestamp(),
                'nonce' => 'n-0S6_WzA2Mj',
                'amr' => ['pwd'],
                'at_hash' => 'the-at-hash',
                'email' => 'ada@example.com',
                'email_verified' => false,
            ],
            $claims,
        );
    }

    public function testWhatIsNotKnownIsLeftOut(): void
    {
        $claims = IdTokenClaims::issue(
            self::ISSUER,
            $this->user,
            ClientId::fromString('spa'),
            $this->scope('openid'),
            null,
            AuthenticationContext::unknown(),
            'the-at-hash',
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
            300,
        )->toArray();

        self::assertArrayNotHasKey('auth_time', $claims);
        self::assertArrayNotHasKey('nonce', $claims);
        self::assertArrayNotHasKey('amr', $claims);
        self::assertSame(['iss', 'sub', 'aud', 'exp', 'iat', 'at_hash'], array_keys($claims));
    }

    private function scope(string $scope): ScopeSet
    {
        return ScopeSet::fromString($scope);
    }
}
