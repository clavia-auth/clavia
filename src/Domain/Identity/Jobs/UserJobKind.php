<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Identity\Jobs;

/** What a bulk job does. */
enum UserJobKind: string
{
    /** Creates the accounts of an NDJSON file in one pool, line by line. */
    case Import = 'users_import';

    /** Writes the accounts of one connection out as NDJSON, never with a password hash. */
    case Export = 'users_export';
}
