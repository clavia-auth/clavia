<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Provisioning;

use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\InvalidValue;
use DateTimeImmutable;

/**
 * What lets a directory (Entra ID, Okta, Google Workspace) reach `/scim/v2`
 * (docs/design/scim-provisioning.md §2): a secret an operator hands out, bound to one connection,
 * which is where every account it creates, reads or changes lives; good until a date and
 * revocable at any time.
 *
 * Like an initial access token, it is a credential of its own kind and no Management API access
 * token: a directory is configured with a base URL and a secret, and has no way to refresh an
 * OAuth token. The secret is handed out once and stored as its digest.
 *
 * It expires because a token pasted into a directory's settings is forgotten there: a year by
 * default, two at most, flagged within thirty days of the end (§10, question 4).
 */
final readonly class ProvisioningToken
{
    public const int MAX_DESCRIPTION_LENGTH = 120;
    public const int MIN_LIFETIME_SECONDS = 86_400;
    public const int DEFAULT_LIFETIME_SECONDS = 31_536_000;
    public const int MAX_LIFETIME_SECONDS = 63_072_000;
    /** How long before its expiry a token is flagged to the operator. */
    public const int EXPIRING_SOON_SECONDS = 2_592_000;

    /** @param non-empty-string $description */
    private function __construct(
        public ProvisioningTokenId $id,
        public Digest $digest,
        public ConnectionName $connection,
        public string $description,
        public DateTimeImmutable $createdAt,
        public DateTimeImmutable $expiresAt,
        public ?DateTimeImmutable $revokedAt,
        public SubjectAttribute $subjectAttribute,
        public bool $addressesTrusted,
        public bool $deleteDeactivates,
    ) {
    }

    /**
     * A new token.
     *
     * @param Digest $digest            The digest of the secret handed out; the secret itself is never kept.
     * @param bool   $addressesTrusted  Whether the directory's addresses are taken as verified (§7).
     * @param bool   $deleteDeactivates Whether a SCIM `DELETE` deactivates rather than deletes (§2).
     *
     * @throws InvalidValue When the description or the lifetime is out of bounds.
     */
    public static function issue(
        ProvisioningTokenId $id,
        Digest $digest,
        ConnectionName $connection,
        string $description,
        DateTimeImmutable $now,
        int $lifetimeSeconds,
        SubjectAttribute $subjectAttribute,
        bool $addressesTrusted,
        bool $deleteDeactivates,
    ): self {
        if ($lifetimeSeconds < self::MIN_LIFETIME_SECONDS || $lifetimeSeconds > self::MAX_LIFETIME_SECONDS) {
            throw new InvalidValue('A provisioning token lives between a day and two years.');
        }

        return self::reconstitute(
            $id,
            $digest,
            $connection,
            $description,
            $now,
            $now->modify(sprintf('+%d seconds', $lifetimeSeconds)),
            null,
            $subjectAttribute,
            $addressesTrusted,
            $deleteDeactivates,
        );
    }

    /**
     * A token as storage holds it. The same rules apply, so a token that exists is coherent.
     *
     * @throws InvalidValue
     */
    public static function reconstitute(
        ProvisioningTokenId $id,
        Digest $digest,
        ConnectionName $connection,
        string $description,
        DateTimeImmutable $createdAt,
        DateTimeImmutable $expiresAt,
        ?DateTimeImmutable $revokedAt,
        SubjectAttribute $subjectAttribute,
        bool $addressesTrusted,
        bool $deleteDeactivates,
    ): self {
        if (
            $description === ''
            || strlen($description) > self::MAX_DESCRIPTION_LENGTH
            || preg_match('/[\x00-\x1F\x7F]/', $description) === 1
        ) {
            throw new InvalidValue('A description is 1 to 120 bytes, without control characters.');
        }
        if ($expiresAt <= $createdAt) {
            throw new InvalidValue('A provisioning token expires after it was issued.');
        }

        return new self(
            $id,
            $digest,
            $connection,
            $description,
            $createdAt,
            $expiresAt,
            $revokedAt,
            $subjectAttribute,
            $addressesTrusted,
            $deleteDeactivates,
        );
    }

    /** Whether it reaches `/scim/v2` now: neither revoked nor expired. */
    public function isUsableAt(DateTimeImmutable $now): bool
    {
        return $this->stateAt($now) === ProvisioningTokenState::Active;
    }

    /** Revoked first, then expired: what stops it, in the order an operator acts on. */
    public function stateAt(DateTimeImmutable $now): ProvisioningTokenState
    {
        return match (true) {
            $this->revokedAt !== null => ProvisioningTokenState::Revoked,
            $now >= $this->expiresAt => ProvisioningTokenState::Expired,
            default => ProvisioningTokenState::Active,
        };
    }

    /**
     * Whether a usable token stops within thirty days: the operator must issue another and give it
     * to the directory before provisioning stops.
     */
    public function isExpiringSoonAt(DateTimeImmutable $now): bool
    {
        return $this->isUsableAt($now)
            && $this->expiresAt->getTimestamp() - $now->getTimestamp() <= self::EXPIRING_SOON_SECONDS;
    }

    /**
     * The token, stopped at once. The accounts it provisioned stay. Revoking it twice keeps the
     * first instant.
     */
    public function revoke(DateTimeImmutable $now): self
    {
        return $this->revokedAt !== null ? $this : clone($this, ['revokedAt' => $now]);
    }
}
