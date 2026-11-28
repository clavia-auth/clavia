<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Provisioning;

use Clavia\Application\Authorization\AuthorizationPermission;
use Clavia\Domain\ResourceServer\Permission;
use Clavia\Domain\ResourceServer\ResourceServer;
use Clavia\Domain\Shared\Audience;

/**
 * Register, or bring up to date, the Authorization API (docs/design/fine-grained-authorization.md
 * §2): the system API an API's own client is granted on to ask for decisions, with
 * {@see AuthorizationPermission}'s scopes. Run by `clavia management-api:register` when fine-grained
 * authorization is on.
 *
 * A system API, so a third-party client never gets a token for it, and its scopes cannot be widened
 * by any endpoint.
 */
final readonly class RegisterAuthorizationApi
{
    public const string NAME = 'Clavia Authorization API';

    /**
     * @param Audience $identifier `https://management.{domain}/access`.
     */
    public function __construct(
        private SystemApiRegistration $registration,
        private Audience $identifier,
    ) {
    }

    public function __invoke(): ResourceServer
    {
        return $this->registration->register(
            $this->identifier,
            self::NAME,
            array_map(
                static fn (AuthorizationPermission $permission): Permission => Permission::of(
                    $permission->value,
                    $permission->description(),
                ),
                AuthorizationPermission::cases(),
            ),
        );
    }
}
