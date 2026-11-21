<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\OAuth2\Device;

use Clavia\Domain\Client\ClientId;

/**
 * The person is signed in through a connection the device's application does not enable,
 * so their session counts for nothing here: they sign in again, through one the login
 * page will offer for that application, and come back to the same code.
 */
final readonly class DeviceSignInRequired
{
    public function __construct(
        public ClientId $clientId,
        public string $userCode,
    ) {
    }
}
