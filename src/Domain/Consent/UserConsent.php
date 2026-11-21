<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Consent;

use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\ResourceServer\ResourceServerId;
use Clavia\Domain\Shared\ScopeSet;
use DateTimeImmutable;

/**
 * What a person agreed, on the consent screen, to let one application do as them on one
 * API: "may *this application* have *these scopes* there, acting as me?"
 *
 * Kept so the question is not asked again, and keyed on exactly those three things. The
 * API is the one the request named in `audience`, or none for a request asking for the
 * OpenID Connect scopes alone: `read:users` on two APIs are two permissions, so consenting
 * to one says nothing about the other. The scope accumulates — a later request for more
 * asks again and the answer widens the record — and a request for less is covered
 * without asking.
 *
 * Neither a token nor a session. Withdrawing a consent stops the *next* authorization;
 * tokens already issued run to their own expiry or revocation.
 */
final readonly class UserConsent
{
    private function __construct(
        public UserId $userId,
        public ClientId $clientId,
        public ?ResourceServerId $resourceServerId,
        public ScopeSet $scope,
        public DateTimeImmutable $grantedAt,
        public DateTimeImmutable $updatedAt,
    ) {
    }

    /**
     * The first answer for this person, application and API.
     *
     * @param ResourceServerId|null $resourceServerId The API the request named; null for none.
     * @param ScopeSet              $scope            Everything the request asked for, OIDC scopes included.
     */
    public static function give(
        UserId $userId,
        ClientId $clientId,
        ?ResourceServerId $resourceServerId,
        ScopeSet $scope,
        DateTimeImmutable $at,
    ): self {
        return new self($userId, $clientId, $resourceServerId, $scope, $at, $at);
    }

    /** A consent read back from storage. */
    public static function reconstitute(
        UserId $userId,
        ClientId $clientId,
        ?ResourceServerId $resourceServerId,
        ScopeSet $scope,
        DateTimeImmutable $grantedAt,
        DateTimeImmutable $updatedAt,
    ): self {
        return new self($userId, $clientId, $resourceServerId, $scope, $grantedAt, $updatedAt);
    }

    /** Whether every scope of `$scope` was agreed to already. */
    public function covers(ScopeSet $scope): bool
    {
        return $scope->isSubsetOf($this->scope);
    }

    /**
     * The same consent, widened to `$scope` as well: the person has now agreed to the
     * union. Unchanged — `updatedAt` included — when it already covered it.
     */
    public function widenedBy(ScopeSet $scope, DateTimeImmutable $at): self
    {
        if ($this->covers($scope)) {
            return $this;
        }

        return new self(
            $this->userId,
            $this->clientId,
            $this->resourceServerId,
            $this->scope->union($scope),
            $this->grantedAt,
            $at,
        );
    }
}
