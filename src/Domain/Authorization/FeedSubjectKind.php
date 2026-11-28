<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Authorization;

/**
 * The kinds of {@see FeedSubject}, named as the types Clavia reserves in a model.
 */
enum FeedSubjectKind: string
{
    case User = 'user';
    case Role = 'role';
    case Client = 'client';
    case EveryRole = '*';
}
