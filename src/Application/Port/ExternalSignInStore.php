<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Port;

use Clavia\Domain\Authentication\PendingExternalSignIn;

/**
 * Sign-ins sent out to an external provider, keyed by the `state` handle that went with
 * them, for {@see PendingExternalSignIn::LIFETIME_SECONDS}. Stored as the handle's
 * digest, like every handle a browser holds.
 */
interface ExternalSignInStore
{
    /**
     * @param non-empty-string $handle
     */
    public function open(#[\SensitiveParameter] string $handle, PendingExternalSignIn $pending): void;

    /**
     * Read **and remove** the pending sign-in, atomically: a `state` is redeemable once,
     * even by two requests racing with it.
     */
    public function claim(#[\SensitiveParameter] string $handle): ?PendingExternalSignIn;
}
