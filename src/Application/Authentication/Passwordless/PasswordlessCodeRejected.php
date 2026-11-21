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
 * A wrong code, with attempts left: the same page again.
 */
final readonly class PasswordlessCodeRejected
{
    public function __construct(public PasswordlessPrompt $prompt)
    {
    }
}
