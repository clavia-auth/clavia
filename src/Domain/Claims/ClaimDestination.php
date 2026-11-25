<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Claims;

/** Where a custom claim goes. An API's mappings go to its access tokens only. */
enum ClaimDestination: string
{
    case AccessToken = 'access_token';
    case IdToken = 'id_token';
    case UserInfo = 'userinfo';
}
