<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Clients\Registration;

use Clavia\Domain\Client\Client;
use Clavia\Domain\Client\Registration\ClientRegistration;

/**
 * A self-registered client as its configuration endpoint describes it (RFC 7592 §3), with the new
 * registration access token after an update, handed out this once.
 */
final readonly class ClientConfiguration
{
    /** @param non-empty-string|null $registrationAccessToken */
    public function __construct(
        public Client $client,
        public ClientRegistration $registration,
        #[\SensitiveParameter] public ?string $registrationAccessToken = null,
    ) {
    }
}
