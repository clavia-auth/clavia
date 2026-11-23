<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Clients\Registration;

use RuntimeException;

/**
 * The client address asked for too many registrations within the window: `429`, with how long to
 * wait.
 */
final class TooManyRegistrations extends RuntimeException
{
    /** @param positive-int $retryAfterSeconds */
    public function __construct(public readonly int $retryAfterSeconds)
    {
        parent::__construct('Too many client registrations from this address.');
    }
}
