<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Identity\Jobs;

use Clavia\Domain\Shared\UuidId;

/** Identifies a bulk job on the users: what the Management API names it by. */
final readonly class UserJobId extends UuidId
{
}
