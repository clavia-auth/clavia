<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\OAuth2;

use Clavia\Domain\Authentication\AuthenticationContext;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Oidc\Nonce;
use Clavia\Domain\Shared\Audience;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\ScopeSet;
use DateTimeImmutable;

/**
 * A single-use authorization code, bound to a client, a user, a redirect URI and a
 * PKCE challenge (RFC 6749 §4.1.2, RFC 7636) — or, for a confidential client relieved of
 * PKCE, to the OpenID Connect `nonce` its ID token will carry (OAuth 2.1 §7.5.1).
 *
 * The code itself exists only in the redirect that hands it to the client; what is kept
 * is its digest. The record is never deleted on redemption: `usedAt` is what lets a
 * replayed code be told apart from an unknown one, and a replay carries an obligation —
 * revoke what the code produced — that a deleted row would silently drop.
 */
final class AuthorizationCode
{
    private function __construct(
        public readonly AuthorizationCodeId $id,
        public readonly Digest $digest,
        public readonly ClientId $clientId,
        public readonly UserId $userId,
        public readonly string $redirectUri,
        public readonly ScopeSet $scope,
        public readonly ?CodeChallenge $challenge,
        public readonly ?Audience $audience,
        public readonly ?Nonce $nonce,
        public readonly AuthenticationContext $authentication,
        public readonly DateTimeImmutable $expiresAt,
        private ?DateTimeImmutable $usedAt,
        public readonly DateTimeImmutable $createdAt,
    ) {
    }

    /**
     * Record a code that was just generated.
     *
     * Everything the token endpoint will later check is bound here.
     *
     * @param string       $redirectUri     The `redirect_uri` the response is being sent to, exactly as
     *                                      validated; the token request must present the same one.
     * @param Audience|null $audience       The API the request named; its permissions bounded the scope.
     * @param CodeChallenge|null $challenge Null only for a client relieved of PKCE, and then with a nonce.
     * @param Nonce|null   $nonce           The `nonce` of an OpenID Connect request, for the ID token.
     * @param positive-int $lifetimeSeconds OAuth 2.1 recommends one minute at most.
     *
     * @throws InvalidValue When the code would be bound by neither a challenge nor a nonce.
     */
    public static function issue(
        AuthorizationCodeId $id,
        Digest $digest,
        ClientId $clientId,
        UserId $userId,
        string $redirectUri,
        ScopeSet $scope,
        ?CodeChallenge $challenge,
        ?Audience $audience,
        ?Nonce $nonce,
        AuthenticationContext $authentication,
        DateTimeImmutable $now,
        int $lifetimeSeconds,
    ): self {
        if ($challenge === null && $nonce === null) {
            throw new InvalidValue('A code without a PKCE challenge is bound to its client by a nonce instead.');
        }

        return new self(
            $id,
            $digest,
            $clientId,
            $userId,
            $redirectUri,
            $scope,
            $challenge,
            $audience,
            $nonce,
            $authentication,
            $now->modify(sprintf('+%d seconds', $lifetimeSeconds)),
            null,
            $now,
        );
    }

    /** Rebuild a code from storage. */
    public static function reconstitute(
        AuthorizationCodeId $id,
        Digest $digest,
        ClientId $clientId,
        UserId $userId,
        string $redirectUri,
        ScopeSet $scope,
        ?CodeChallenge $challenge,
        ?Audience $audience,
        ?Nonce $nonce,
        AuthenticationContext $authentication,
        DateTimeImmutable $expiresAt,
        ?DateTimeImmutable $usedAt,
        DateTimeImmutable $createdAt,
    ): self {
        return new self(
            $id,
            $digest,
            $clientId,
            $userId,
            $redirectUri,
            $scope,
            $challenge,
            $audience,
            $nonce,
            $authentication,
            $expiresAt,
            $usedAt,
            $createdAt,
        );
    }

    /**
     * Try to spend the code on behalf of the client presenting it.
     *
     * The order of the checks is the point. A code presented by the wrong client tells
     * that client nothing and changes nothing. A code already spent is a replay,
     * whoever presents it now. An expired code is refused *without* being spent, so
     * that "used" keeps meaning "redeemed". Only then is it spent — before the redirect
     * URI and the PKCE verifier are looked at, so a wrong guess at either burns the code.
     *
     * Must be called on a row locked for the duration of the decision
     * ({@see AuthorizationCodeRepository::lockForRedemption()}): two concurrent
     * redemptions must not both see an unspent code.
     */
    #[\NoDiscard]
    public function redeem(ClientId $presentedBy, DateTimeImmutable $now): Redemption
    {
        if (! $this->clientId->equals($presentedBy)) {
            return Redemption::IssuedToAnotherClient;
        }

        if ($this->usedAt !== null) {
            return Redemption::Replayed;
        }

        if ($this->expiresAt <= $now) {
            return Redemption::Expired;
        }

        $this->usedAt = $now;

        return Redemption::Redeemed;
    }

    public function usedAt(): ?DateTimeImmutable
    {
        return $this->usedAt;
    }
}
