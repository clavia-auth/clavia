<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Identity\Jobs;

/** Where a bulk job stands. */
enum UserJobStatus: string
{
    /** Waiting for `clavia jobs:run`. */
    case Queued = 'queued';

    /** Being processed by one worker. */
    case Running = 'running';

    /** Done: every line was taken or refused, and the report says which. */
    case Completed = 'completed';

    /** Stopped as a whole, before the end (a worker that never finished, say): `failure` says why. */
    case Failed = 'failed';
}
