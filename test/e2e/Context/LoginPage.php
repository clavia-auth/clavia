<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\E2e\Context;

/** The sign-in page of an authorization request, as the form on it will be posted. */
final readonly class LoginPage
{
    public function __construct(public string $html, public string $csrfToken, public string $handle)
    {
    }
}
