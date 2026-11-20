<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Oidc;

/**
 * The scope values OpenID Connect defines (OIDC Core §3.1.2.1, §5.4).
 */
final class OidcScope
{
    /** Makes an authorization request an OpenID Connect authentication request. */
    public const string OPENID = 'openid';

    public const string PROFILE = 'profile';

    public const string EMAIL = 'email';

    private function __construct()
    {
    }
}
