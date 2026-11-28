<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authorization\Caller;

use Clavia\Application\Authorization\AuthorizationPermission;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\OAuth2\BearerTokenError;
use Clavia\Domain\Shared\ScopeSet;

/**
 * Who is calling the Authorization API (`/access/v1/*`), from its access token: the client the token
 * was issued to, which says which API it speaks for, and the scopes it carries.
 */
final readonly class AuthorizationCaller
{
    public function __construct(
        public ClientId $clientId,
        public ?UserId $userId,
        public ScopeSet $scopes,
    ) {
    }

    /**
     * @throws BearerTokenError `insufficient_scope`, naming the permission needed.
     */
    public function require(AuthorizationPermission $permission): void
    {
        if (! $this->scopes->contains($permission->value)) {
            throw BearerTokenError::insufficientScope(
                ScopeSet::fromString($permission->value),
                sprintf("The access token does not carry the '%s' scope.", $permission->value),
            );
        }
    }
}
