<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\OAuth2\TokenManagement;

use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Shared\Audience;
use Clavia\Domain\Shared\ScopeSet;
use DateTimeImmutable;

/**
 * What introspection says about an active token (RFC 7662 §2.2).
 */
final readonly class TokenIntrospection
{
    /**
     * @param UserId|null $subject   The person it was issued on behalf of; none for a client acting as itself.
     * @param string|null $username  The person's address, for people reading the answer.
     * @param string|null $tokenType `Bearer` for an access token; a refresh token is presented to no API.
     * @param DateTimeImmutable|null $authenticatedAt When the person signed in to authorize it (`auth_time`, RFC 9470
     *                                                §6.2); null for a client acting as itself, or a sign-in this
     *                                                server did not witness.
     * @param string|null            $acr             The level of that sign-in; null for one factor.
     * @param string|null            $dpopJkt         The thumbprint of the DPoP key it is bound to (RFC 9449
     *                                                §6.2); null for a bearer token.
     */
    public function __construct(
        public ClientId $clientId,
        public ScopeSet $scope,
        public DateTimeImmutable $issuedAt,
        public DateTimeImmutable $expiresAt,
        public ?Audience $audience,
        public ?UserId $subject,
        public ?string $username,
        public ?string $tokenType,
        public ?DateTimeImmutable $authenticatedAt = null,
        public ?string $acr = null,
        public ?string $dpopJkt = null,
        /** @var array<non-empty-string, mixed> The API's custom claims, worked out when asked. */
        public array $claims = [],
    ) {
    }
}
