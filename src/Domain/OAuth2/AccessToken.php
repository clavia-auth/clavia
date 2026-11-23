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
use Clavia\Domain\OAuth2\Dpop\JwkThumbprint;
use Clavia\Domain\Shared\Audience;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\ScopeSet;
use DateTimeImmutable;

/**
 * An issued access token (RFC 6750 bearer).
 *
 * Recorded by the digest of the value the client holds — a random string, or the JWT of
 * an API that takes them (RFC 9068) — and looked up by it here, which is what lets every
 * surface of this server that accepts a token honour revocation the instant it happens.
 * `authorizationCodeId` records which code minted it, so a replayed code can revoke
 * everything it produced (RFC 6749 §4.1.2) — including what was later minted from the
 * refresh tokens that code started. `audience` is the API the token is for — its
 * `aud` — when the client named one. `refreshFamilyId` is the refresh token family it
 * came with or from, so revoking the family takes it along.
 */
final class AccessToken
{
    public const string TOKEN_TYPE = 'Bearer';

    /** The `token_type` of a token bound to a DPoP key (RFC 9449 §5). */
    public const string DPOP_TOKEN_TYPE = 'DPoP';

    private function __construct(
        public readonly AccessTokenId $id,
        public readonly Digest $digest,
        public readonly ClientId $clientId,
        public readonly ?UserId $userId,
        public readonly ?AuthorizationCodeId $authorizationCodeId,
        public readonly ?Audience $audience,
        public readonly ScopeSet $scope,
        public readonly DateTimeImmutable $issuedAt,
        public readonly DateTimeImmutable $expiresAt,
        private ?DateTimeImmutable $revokedAt,
        public readonly ?RefreshTokenId $refreshFamilyId,
        public readonly AuthenticationContext $authentication,
        public readonly ?JwkThumbprint $dpopJkt = null,
    ) {
    }

    /**
     * Record a token minted by redeeming an authorization code, for the user who
     * approved it.
     *
     * @param positive-int $lifetimeSeconds
     * @param RefreshTokenId|null $refreshFamily The family of the refresh token issued with it, if any.
     */
    public static function issueFromCode(
        AccessTokenId $id,
        Digest $digest,
        AuthorizationCode $code,
        ScopeSet $scope,
        DateTimeImmutable $now,
        int $lifetimeSeconds,
        ?RefreshTokenId $refreshFamily = null,
    ): self {
        return new self(
            $id,
            $digest,
            $code->clientId,
            $code->userId,
            $code->id,
            $code->audience,
            $scope,
            $now,
            $now->modify(sprintf('+%d seconds', $lifetimeSeconds)),
            null,
            $refreshFamily,
            $code->authentication->withoutSession(),
        );
    }

    /**
     * A token issued on a person's behalf by a grant other than the code flow — the device
     * grant: no authorization code to trace it to.
     *
     * @param AuthenticationContext $authentication How the person signed in to approve it.
     * @param RefreshTokenId|null   $refreshFamily  The family issued alongside, if any.
     */
    public static function issueForUser(
        AccessTokenId $id,
        Digest $digest,
        ClientId $clientId,
        UserId $userId,
        ?Audience $audience,
        ScopeSet $scope,
        DateTimeImmutable $now,
        int $lifetimeSeconds,
        AuthenticationContext $authentication,
        ?RefreshTokenId $refreshFamily = null,
    ): self {
        return new self(
            $id,
            $digest,
            $clientId,
            $userId,
            null,
            $audience,
            $scope,
            $now,
            $now->modify(sprintf('+%d seconds', $lifetimeSeconds)),
            null,
            $refreshFamily,
            $authentication->withoutSession(),
        );
    }

    /**
     * Record a token minted by a refresh, issued with `$refreshToken`, the successor of
     * the token just spent. It inherits the person, the API, the code, the family, and how
     * the person signed in when the family started (RFC 9470 §6.1).
     *
     * @param positive-int $lifetimeSeconds
     */
    public static function issueFromRefresh(
        AccessTokenId $id,
        Digest $digest,
        RefreshToken $refreshToken,
        ScopeSet $scope,
        DateTimeImmutable $now,
        int $lifetimeSeconds,
    ): self {
        return new self(
            $id,
            $digest,
            $refreshToken->clientId,
            $refreshToken->userId,
            $refreshToken->authorizationCodeId,
            $refreshToken->audience,
            $scope,
            $now,
            $now->modify(sprintf('+%d seconds', $lifetimeSeconds)),
            null,
            $refreshToken->familyId,
            $refreshToken->authentication,
        );
    }

    /**
     * Record a token a client obtained as itself (RFC 6749 §4.4): no subject, no code,
     * and the API it is for.
     *
     * The missing subject is the point. Such a token represents a machine, and every
     * surface that answers questions about a person must refuse it.
     *
     * @param positive-int $lifetimeSeconds
     */
    public static function issueToClient(
        AccessTokenId $id,
        Digest $digest,
        ClientId $clientId,
        Audience $audience,
        ScopeSet $scope,
        DateTimeImmutable $now,
        int $lifetimeSeconds,
    ): self {
        return new self(
            $id,
            $digest,
            $clientId,
            null,
            null,
            $audience,
            $scope,
            $now,
            $now->modify(sprintf('+%d seconds', $lifetimeSeconds)),
            null,
            null,
            AuthenticationContext::unknown(),
        );
    }

    /** Rebuild a token from storage. */
    public static function reconstitute(
        AccessTokenId $id,
        Digest $digest,
        ClientId $clientId,
        ?UserId $userId,
        ?AuthorizationCodeId $authorizationCodeId,
        ?Audience $audience,
        ScopeSet $scope,
        DateTimeImmutable $issuedAt,
        DateTimeImmutable $expiresAt,
        ?DateTimeImmutable $revokedAt,
        ?RefreshTokenId $refreshFamilyId = null,
        ?AuthenticationContext $authentication = null,
        ?JwkThumbprint $dpopJkt = null,
    ): self {
        return new self(
            $id,
            $digest,
            $clientId,
            $userId,
            $authorizationCodeId,
            $audience,
            $scope,
            $issuedAt,
            $expiresAt,
            $revokedAt,
            $refreshFamilyId,
            $authentication ?? AuthenticationContext::unknown(),
            $dpopJkt,
        );
    }

    /**
     * The same token, known by the digest of another value: the JWT that describes it,
     * which can only be signed once the token it describes exists.
     */
    public function presentedAs(Digest $digest): self
    {
        return self::reconstitute(
            $this->id,
            $digest,
            $this->clientId,
            $this->userId,
            $this->authorizationCodeId,
            $this->audience,
            $this->scope,
            $this->issuedAt,
            $this->expiresAt,
            $this->revokedAt,
            $this->refreshFamilyId,
            $this->authentication,
            $this->dpopJkt,
        );
    }

    /** The same token, revoked at `$now` — or as it was, when already revoked. */
    public function revoked(DateTimeImmutable $now): self
    {
        return self::reconstitute(
            $this->id,
            $this->digest,
            $this->clientId,
            $this->userId,
            $this->authorizationCodeId,
            $this->audience,
            $this->scope,
            $this->issuedAt,
            $this->expiresAt,
            $this->revokedAt ?? $now,
            $this->refreshFamilyId,
            $this->authentication,
            $this->dpopJkt,
        );
    }

    /**
     * The same token, bound to the key of a DPoP proof (RFC 9449 §6): only a fresh proof from that
     * key makes it usable, wherever it is presented.
     */
    public function boundTo(JwkThumbprint $key): self
    {
        return self::reconstitute(
            $this->id,
            $this->digest,
            $this->clientId,
            $this->userId,
            $this->authorizationCodeId,
            $this->audience,
            $this->scope,
            $this->issuedAt,
            $this->expiresAt,
            $this->revokedAt,
            $this->refreshFamilyId,
            $this->authentication,
            $key,
        );
    }

    /**
     * `DPoP` for a token bound to a key (RFC 9449 §5), `Bearer` otherwise.
     *
     * @return non-empty-string
     */
    public function tokenType(): string
    {
        return $this->dpopJkt === null ? self::TOKEN_TYPE : self::DPOP_TOKEN_TYPE;
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
