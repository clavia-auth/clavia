<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication;

use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Identity\UserRepository;
use LogicException;

/**
 * Development stand-in for a signed-in session (`CLAVIA_DEV_AUTOLOGIN_EMAIL`).
 *
 * With it configured, the authorization endpoint treats the named account as signed in
 * whenever nobody is — which lets a script exercise the whole flow without a browser.
 * It **bypasses authentication**. The settings already refuse to be built with it
 * outside development; the check is repeated here because the cost of the two guards
 * disagreeing is a complete authentication bypass: anyone able to reach
 * `/oauth2/authorize` would receive codes for this account without presenting a
 * credential.
 */
final readonly class DevelopmentAutoLogin
{
    /**
     * @param string|null $email         The account to sign in as; null when the shortcut is off.
     * @param bool        $isDevelopment Whether this deployment is a development one.
     */
    public function __construct(
        private UserRepository $users,
        private ?string $email,
        private bool $isDevelopment,
    ) {
    }

    /**
     * The configured account, when the shortcut is on and the account exists and is active.
     *
     * @throws LogicException When reached outside development.
     */
    public function endUser(): ?EndUser
    {
        if ($this->email === null || $this->email === '') {
            return null;
        }

        if (! $this->isDevelopment) {
            throw new LogicException('Development auto-login reached in a non-development environment.');
        }

        $user = $this->users->findByEmail(ConnectionName::defaultPool(), $this->email);

        return $user !== null && $user->isActive() ? new EndUser($user->id) : null;
    }
}
