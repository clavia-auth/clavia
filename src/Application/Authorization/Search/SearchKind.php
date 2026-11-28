<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authorization\Search;

/** What a search looks for (AuthZEN 1.0 §8.4–§8.6). */
enum SearchKind: string
{
    case Subject = 'subject';
    case Resource = 'resource';
    case Action = 'action';
}
