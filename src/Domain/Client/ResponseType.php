<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Client;

/**
 * What the authorization endpoint may return. Only `code`: the implicit grant
 * (`token`) is gone in OAuth 2.1.
 */
enum ResponseType: string
{
    case Code = 'code';
}
