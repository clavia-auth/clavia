<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Users;

use Clavia\Domain\Authentication\Session;
use Clavia\Domain\Client\Client;

/**
 * One browser session of an account, as an operator sees it: when and how it began, when
 * it ends at the latest, and the applications that signed in through it — the ones that
 * ending it will tell. Never the cookie: nothing outside the browser holds it.
 */
final readonly class ManagedSession
{
    /**
     * @param list<Client> $clients The applications still registered among those that signed in.
     */
    public function __construct(
        public Session $session,
        public array $clients,
    ) {
    }
}
