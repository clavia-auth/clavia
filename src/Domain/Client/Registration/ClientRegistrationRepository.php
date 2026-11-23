<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Client\Registration;

use Clavia\Domain\Client\ClientId;

/**
 * The registrations of clients that registered themselves. Deleting a client deletes its
 * registration (a foreign key that cascades).
 */
interface ClientRegistrationRepository
{
    public function add(ClientRegistration $registration): void;

    public function find(ClientId $clientId): ?ClientRegistration;
}
