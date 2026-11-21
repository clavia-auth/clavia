<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\OAuth2\Device;

/**
 * The person's decision is recorded: the device hears it at its next poll.
 */
final readonly class DeviceDecided
{
    /**
     * @param bool $approved False for a refusal — the person's, or the server's on their behalf.
     * @param bool $noPermission The person allowed it, but holds nothing on the API it is for, so
     *                           it was refused all the same.
     */
    public function __construct(
        public bool $approved,
        public bool $noPermission = false,
    ) {
    }
}
