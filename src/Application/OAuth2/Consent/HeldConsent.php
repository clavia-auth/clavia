<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\OAuth2\Consent;

use Clavia\Domain\Client\Client;
use Clavia\Domain\Consent\PendingConsent;
use Clavia\Domain\Identity\User;
use Clavia\Domain\ResourceServer\ResourceServer;

/**
 * A request on hold for the consent screen, with what it names as it is now.
 */
final readonly class HeldConsent
{
    public function __construct(
        public PendingConsent $pending,
        public User $user,
        public Client $client,
        public ?ResourceServer $api,
    ) {
    }
}
