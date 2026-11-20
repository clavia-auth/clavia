<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Shared;

use DomainException;

/**
 * Something the caller meant to create already exists: an address another account
 * uses, an API identifier already registered.
 *
 * Thrown by storage when its uniqueness constraint decides, which is the only answer
 * that holds under concurrency: a "does it exist?" check before inserting leaves a
 * window for another request to insert the same thing.
 */
final class AlreadyExists extends DomainException
{
}
