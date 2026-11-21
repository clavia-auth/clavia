<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\OAuth2\Event;

use Clavia\Domain\Client\GrantType;
use Clavia\Domain\OAuth2\AccessToken;
use Clavia\Domain\Shared\DomainEvent;

/**
 * An access token was issued, by any grant — the token's record, never its value.
 */
final readonly class AccessTokenIssued implements DomainEvent
{
    /**
     * @param bool $withRefreshToken Whether a refresh token came with it.
     */
    public function __construct(
        public AccessToken $token,
        public GrantType $grant,
        public bool $withRefreshToken,
    ) {
    }
}
