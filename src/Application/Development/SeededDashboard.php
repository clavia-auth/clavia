<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Development;

use Clavia\Domain\Client\ClientId;

/**
 * The dashboard's registration, and whether this run created it.
 */
final readonly class SeededDashboard
{
    public function __construct(
        public ClientId $clientId,
        public bool $created,
    ) {
    }
}
