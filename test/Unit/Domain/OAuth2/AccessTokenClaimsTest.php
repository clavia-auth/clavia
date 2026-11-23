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
use Clavia\Domain\Authentication\AuthenticationMethod;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\OAuth2\AccessToken;
use Clavia\Domain\OAuth2\AccessTokenClaims;
use Clavia\Domain\OAuth2\AccessTokenId;
use Clavia\Domain\Shared\Audience;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\ScopeSet;
use DateTimeImmutable;
use LogicException;
use PHPUnit\Framework\TestCase;

/**
 * The claims of a JWT access token, RFC 9068 §2.2.
 */
final class AccessTokenClaimsTest extends TestCase
{
    private const string ISSUER = 'https://auth.clavia.test';
    private const string TOKEN_ID = '6f1c2b0e-8a4d-4c3e-9b5a-1d2e3f4a5b6c';
    private const string USER_ID = '0b7e3d9a-2c41-4f6e-8a1b-5c9d0e7f3a24';
    private const string API = 'https://invoices.test/api/';

    public function testAPersonsTokenCarriesEveryRequiredClaim(): void
    {
        $token = AccessToken::issueForUser(
            AccessTokenId::fromString(self::TOKEN_ID),
            Digest::of('value'),
            ClientId::fromString('web-app'),
            UserId::fromString(self::USER_ID),
            Audience::fromString(self::API),
            ScopeSet::fromString('invoices:read invoices:write'),
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
            3600,
            AuthenticationContext::reconstitute(
                new DateTimeImmutable('2026-01-15T09:58:00Z'),
                [
                    AuthenticationMethod::Password,
                    AuthenticationMethod::OneTimePassword,
                    AuthenticationMethod::MultipleFactors,
                ],
            ),
        );

        self::assertSame([
            'iss' => self::ISSUER,
            'exp' => 1768474800,
            'aud' => self::API,
            'sub' => self::USER_ID,
            'client_id' => 'web-app',
            'iat' => 1768471200,
            'jti' => self::TOKEN_ID,
            'scope' => 'invoices:read invoices:write',
            // RFC 9470 §6.1: when and how strongly the person signed in.
            'auth_time' => 1768471080,
            'acr' => 'http://schemas.openid.net/pape/policies/2007/06/multi-factor',
        ], AccessTokenClaims::of(self::ISSUER, $token)->toArray());
    }

    public function testAClientActingAsItselfIsItsOwnSubject(): void
    {
        // §2.2: with no resource owner, `sub` names the client.
        $claims = AccessTokenClaims::of(self::ISSUER, $this->machineToken(ScopeSet::fromString('invoices:read')))
            ->toArray();

        self::assertSame('m2m-client', $claims['sub']);
        self::assertSame('m2m-client', $claims['client_id']);
    }

    public function testAnEmptyScopeIsLeftOut(): void
    {
        // §2.2.3 describes the granted scope; nothing granted is no claim, not an empty one.
        $claims = AccessTokenClaims::of(self::ISSUER, $this->machineToken(ScopeSet::empty()))->toArray();

        self::assertArrayNotHasKey('scope', $claims);
    }

    public function testOneFactorHasNoAcrAndAnUnwitnessedSignInNoAuthTime(): void
    {
        $oneFactor = $this->personToken(AuthenticationContext::reconstitute(
            new DateTimeImmutable('2026-01-15T09:58:00Z'),
            [AuthenticationMethod::Password],
        ));
        $unknown = $this->personToken(AuthenticationContext::unknown());

        self::assertArrayNotHasKey('acr', AccessTokenClaims::of(self::ISSUER, $oneFactor)->toArray());
        self::assertSame(1768471080, AccessTokenClaims::of(self::ISSUER, $oneFactor)->toArray()['auth_time']);
        self::assertArrayNotHasKey('auth_time', AccessTokenClaims::of(self::ISSUER, $unknown)->toArray());
    }

    public function testATokenForNoApiIsNeverAJwt(): void
    {
        // §2.2 requires `aud`.
        $token = AccessToken::issueForUser(
            AccessTokenId::fromString(self::TOKEN_ID),
            Digest::of('value'),
            ClientId::fromString('web-app'),
            UserId::fromString(self::USER_ID),
            null,
            ScopeSet::fromString('openid'),
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
            3600,
            AuthenticationContext::unknown(),
        );

        $this->expectException(LogicException::class);

        AccessTokenClaims::of(self::ISSUER, $token);
    }

    private function personToken(AuthenticationContext $authentication): AccessToken
    {
        return AccessToken::issueForUser(
            AccessTokenId::fromString(self::TOKEN_ID),
            Digest::of('value'),
            ClientId::fromString('web-app'),
            UserId::fromString(self::USER_ID),
            Audience::fromString(self::API),
            ScopeSet::fromString('invoices:read'),
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
            3600,
            $authentication,
        );
    }

    private function machineToken(ScopeSet $scope): AccessToken
    {
        return AccessToken::issueToClient(
            AccessTokenId::fromString(self::TOKEN_ID),
            Digest::of('value'),
            ClientId::fromString('m2m-client'),
            Audience::fromString(self::API),
            $scope,
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
            3600,
        );
    }
}
