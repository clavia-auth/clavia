<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Port;

/**
 * The external providers this deployment can sign people in through: those configured
 * with both halves of their credentials. An unconfigured provider is not there at all —
 * a button that fails is worse than no button.
 */
interface IdentityProviders
{
    public function find(string $name): ?IdentityProvider;

    /**
     * In the order the login page offers them.
     *
     * @return list<IdentityProvider>
     */
    public function all(): array;
}
