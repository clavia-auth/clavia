<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Caller;

use Clavia\Application\Management\ManagementPermission;
use Clavia\Domain\Audit\Actor;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\OAuth2\BearerTokenError;
use Clavia\Domain\Shared\ScopeSet;

/**
 * Who is calling the Management API, as its access token says: the client that obtained
 * the token, the person it acts for (none for a machine acting as itself), and the
 * scopes it carries.
 */
final readonly class ManagementCaller
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
    public function require(ManagementPermission $permission): void
    {
        if (! $this->scopes->contains($permission->value)) {
            throw BearerTokenError::insufficientScope(
                ScopeSet::fromString($permission->value),
                sprintf("The access token does not carry the '%s' scope.", $permission->value),
            );
        }
    }

    /** Who the trail names: an operator through the application, or a machine client as itself. */
    public function actor(): Actor
    {
        return $this->userId === null
            ? Actor::application($this->clientId)
            : Actor::person($this->userId, $this->clientId);
    }

    public function isClient(ClientId $client): bool
    {
        return $this->clientId->equals($client);
    }

    public function isActingAs(UserId $user): bool
    {
        return $this->userId?->equals($user) ?? false;
    }
}
