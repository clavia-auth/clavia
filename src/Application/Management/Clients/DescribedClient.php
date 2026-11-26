<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Clients;

use Clavia\Domain\Client\Client;
use Clavia\Domain\Client\Registration\ClientRegistration;

/**
 * A client as the Management API shows it: with its registration, when it registered itself
 * (RFC 7591), so an operator sees which initial access token let it in, and when.
 */
final readonly class DescribedClient
{
    public function __construct(
        public Client $client,
        public ?ClientRegistration $registration,
        public ?string $logoVersion = null,
    ) {
    }
}
