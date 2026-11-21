<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication;

use Clavia\Application\Port\LoginStateStore;
use Clavia\Domain\Authentication\LocalPath;
use Clavia\Domain\Authentication\LoginState;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Shared\SecretGenerator;

/**
 * Send someone who reached a page needing a session to the login page first, holding
 * where they were going server-side behind a handle — never in the URL.
 */
final readonly class RequireSignIn
{
    public function __construct(
        private LoginStateStore $loginStates,
        private SecretGenerator $secrets,
    ) {
    }

    /**
     * @param ClientId|null $for The application the sign-in is for, when there is one: the login
     *                           page then offers the connections it enables.
     *
     * @return non-empty-string The handle the login page takes as `state`.
     */
    public function __invoke(LocalPath $returnTo, ?ClientId $for = null): string
    {
        $handle = $this->secrets->token();
        $this->loginStates->put($handle, new LoginState($returnTo->value, $for));

        return $handle;
    }
}
