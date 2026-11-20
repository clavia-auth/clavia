<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\OAuth2;

use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\ScopeSet;
use DateTimeImmutable;

/**
 * An issued access token (RFC 6750 bearer).
 *
 * Opaque: a random string whose digest is looked up here, which is what lets every
 * surface that accepts a token honour revocation the instant it happens.
 * `authorizationCodeId` records which code minted it, so a replayed code can revoke
 * everything it produced (RFC 6749 §4.1.2).
 */
final class AccessToken
{
    public const string TOKEN_TYPE = 'Bearer';

    private function __construct(
        public readonly AccessTokenId $id,
        public readonly Digest $digest,
        public readonly ClientId $clientId,
        public readonly ?UserId $userId,
        public readonly ?AuthorizationCodeId $authorizationCodeId,
        public readonly ScopeSet $scope,
        public readonly DateTimeImmutable $issuedAt,
        public readonly DateTimeImmutable $expiresAt,
        private ?DateTimeImmutable $revokedAt,
    ) {
    }

    /**
     * Record a token minted by redeeming an authorization code, for the user who
     * approved it.
     *
     * @param positive-int $lifetimeSeconds
     */
    public static function issueFromCode(
        AccessTokenId $id,
        Digest $digest,
        AuthorizationCode $code,
        ScopeSet $scope,
        DateTimeImmutable $now,
        int $lifetimeSeconds,
    ): self {
        return new self(
            $id,
            $digest,
            $code->clientId,
            $code->userId,
            $code->id,
            $scope,
            $now,
            $now->modify(sprintf('+%d seconds', $lifetimeSeconds)),
            null,
        );
    }

    /** Rebuild a token from storage. */
    public static function reconstitute(
        AccessTokenId $id,
        Digest $digest,
        ClientId $clientId,
        ?UserId $userId,
        ?AuthorizationCodeId $authorizationCodeId,
        ScopeSet $scope,
        DateTimeImmutable $issuedAt,
        DateTimeImmutable $expiresAt,
        ?DateTimeImmutable $revokedAt,
    ): self {
        return new self(
            $id,
            $digest,
            $clientId,
            $userId,
            $authorizationCodeId,
            $scope,
            $issuedAt,
            $expiresAt,
            $revokedAt,
        );
    }

    public function isRevoked(): bool
    {
        return $this->revokedAt !== null;
    }

    public function isExpiredAt(DateTimeImmutable $now): bool
    {
        return $this->expiresAt <= $now;
    }

    /** Whether the token may still be accepted: neither revoked nor expired. */
    public function isActiveAt(DateTimeImmutable $now): bool
    {
        return ! $this->isRevoked() && ! $this->isExpiredAt($now);
    }

    public function revokedAt(): ?DateTimeImmutable
    {
        return $this->revokedAt;
    }

    /** Seconds left before expiry, for the `expires_in` of a token response. */
    public function lifetimeFrom(DateTimeImmutable $now): int
    {
        return max(0, $this->expiresAt->getTimestamp() - $now->getTimestamp());
    }
}
