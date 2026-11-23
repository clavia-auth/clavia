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
use Clavia\Domain\Shared\Audience;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\ScopeSet;
use DateTimeImmutable;
use LogicException;

/**
 * A refresh token (RFC 6749 §1.5, §6): one link in a chain that rotates on every use.
 *
 * Every refresh spends the token presented and issues its successor, so a token is good
 * for exactly one use. That is what makes a leak detectable: a token presented after it
 * was spent means two parties hold the chain, and the whole family — every token
 * descended from one sign-in, and every access token any of them minted — is revoked.
 *
 * Three lifetimes bound it. Its own deadline is the idle limit from when it was issued,
 * so a client that stops refreshing loses the session; the family's deadline is fixed at
 * sign-in and copied down the chain, so no amount of refreshing carries a session past
 * it; and each token's deadline is whichever of the two comes first.
 *
 * Only ever issued on a person's behalf: a client acting as itself gets none
 * (RFC 6749 §4.4.3), so the subject is required.
 */
final class RefreshToken
{
    /**
     * @param ScopeSet $scope The ceiling: what a refresh may ask for. What each access token
     *                        actually carries is this, narrowed again at issuance.
     */
    private function __construct(
        public readonly RefreshTokenId $id,
        public readonly Digest $digest,
        public readonly RefreshTokenId $familyId,
        public readonly ClientId $clientId,
        public readonly UserId $userId,
        public readonly ?AuthorizationCodeId $authorizationCodeId,
        public readonly ScopeSet $scope,
        public readonly ?Audience $audience,
        public readonly DateTimeImmutable $issuedAt,
        public readonly DateTimeImmutable $expiresAt,
        public readonly DateTimeImmutable $familyExpiresAt,
        private ?DateTimeImmutable $usedAt,
        private ?DateTimeImmutable $revokedAt,
        public readonly AuthenticationContext $authentication,
    ) {
    }

    /**
     * The first token of a family, issued when an authorization code is redeemed. The
     * family's deadline starts now.
     *
     * @param ScopeSet     $scope                   What the person authorized: the ceiling of the chain.
     * @param positive-int $idleLifetimeSeconds
     * @param positive-int $absoluteLifetimeSeconds
     */
    public static function startFamily(
        RefreshTokenId $id,
        Digest $digest,
        AuthorizationCode $code,
        ScopeSet $scope,
        DateTimeImmutable $now,
        int $idleLifetimeSeconds,
        int $absoluteLifetimeSeconds,
    ): self {
        return self::startFamilyFor(
            $id,
            $digest,
            $code->clientId,
            $code->userId,
            $code->id,
            $code->audience,
            $scope,
            $now,
            $idleLifetimeSeconds,
            $absoluteLifetimeSeconds,
            $code->authentication,
        );
    }

    /**
     * The first refresh token of a family started by any grant acting for a person: the
     * code flow, or a device approved on another screen (no code to trace it to).
     *
     * The family keeps how the person signed in to authorize it, so every access token it
     * mints reports the same `acr` and `auth_time` (RFC 9470 §6.1); the session, which may end
     * long before the family does, is not kept.
     */
    public static function startFamilyFor(
        RefreshTokenId $id,
        Digest $digest,
        ClientId $clientId,
        UserId $userId,
        ?AuthorizationCodeId $authorizationCodeId,
        ?Audience $audience,
        ScopeSet $scope,
        DateTimeImmutable $now,
        int $idleLifetimeSeconds,
        int $absoluteLifetimeSeconds,
        AuthenticationContext $authentication,
    ): self {
        $familyExpiresAt = self::after($now, $absoluteLifetimeSeconds);

        return new self(
            $id,
            $digest,
            $id,
            $clientId,
            $userId,
            $authorizationCodeId,
            $scope,
            $audience,
            $now,
            min(self::after($now, $idleLifetimeSeconds), $familyExpiresAt),
            $familyExpiresAt,
            null,
            null,
            $authentication->withoutSession(),
        );
    }

    public function succeededBy(
        RefreshTokenId $id,
        Digest $digest,
        ScopeSet $scope,
        DateTimeImmutable $now,
        int $idleLifetimeSeconds,
    ): self {
        return new self(
            $id,
            $digest,
            $this->familyId,
            $this->clientId,
            $this->userId,
            $this->authorizationCodeId,
            $scope,
            $this->audience,
            $now,
            min(self::after($now, $idleLifetimeSeconds), $this->familyExpiresAt),
            $this->familyExpiresAt,
            null,
            null,
            $this->authentication,
        );
    }

    /** Rebuild a token from storage. */
    public static function reconstitute(
        RefreshTokenId $id,
        Digest $digest,
        RefreshTokenId $familyId,
        ClientId $clientId,
        UserId $userId,
        ?AuthorizationCodeId $authorizationCodeId,
        ScopeSet $scope,
        ?Audience $audience,
        DateTimeImmutable $issuedAt,
        DateTimeImmutable $expiresAt,
        DateTimeImmutable $familyExpiresAt,
        ?DateTimeImmutable $usedAt,
        ?DateTimeImmutable $revokedAt,
        ?AuthenticationContext $authentication = null,
    ): self {
        return new self(
            $id,
            $digest,
            $familyId,
            $clientId,
            $userId,
            $authorizationCodeId,
            $scope,
            $audience,
            $issuedAt,
            $expiresAt,
            $familyExpiresAt,
            $usedAt,
            $revokedAt,
            $authentication ?? AuthenticationContext::unknown(),
        );
    }

    /**
     * What this token is to `$presentedBy`, now. Changes nothing: spending is
     * {@see self::spend()}, once every other check has passed.
     */
    public function examine(ClientId $presentedBy, DateTimeImmutable $now): Refresh
    {
        return match (true) {
            ! $this->clientId->equals($presentedBy) => Refresh::IssuedToAnotherClient,
            $this->revokedAt !== null => Refresh::Revoked,
            $this->usedAt !== null => Refresh::Replayed,
            $this->expiresAt <= $now => Refresh::Expired,
            default => Refresh::Usable,
        };
    }

    /**
     * Spend the token on a refresh. Call only on a token {@see self::examine()} found
     * usable, under the lock that makes the spend atomic.
     *
     * @throws LogicException When the token is not usable by its own client.
     */
    public function spend(DateTimeImmutable $now): void
    {
        if ($this->examine($this->clientId, $now) !== Refresh::Usable) {
            throw new LogicException('Only a usable refresh token can be spent.');
        }

        $this->usedAt = $now;
    }

    public function usedAt(): ?DateTimeImmutable
    {
        return $this->usedAt;
    }

    public function revokedAt(): ?DateTimeImmutable
    {
        return $this->revokedAt;
    }

    private static function after(DateTimeImmutable $now, int $seconds): DateTimeImmutable
    {
        return $now->modify(sprintf('+%d seconds', $seconds));
    }
}
