<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);


namespace Clavia\Application\Authentication\Passwordless;

/**
 * A sign-in link is on its way. Nothing is handed to this browser: the link works from
 * whichever one opens it.
 */
final readonly class PasswordlessLinkSent
{
    /**
     * @param non-empty-string $email
     */
    public function __construct(public string $email)
    {
    }
}
