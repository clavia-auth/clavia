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
 * A client just registered (RFC 7591 §3.2.1), with the secrets handed out this once: its client
 * secret, when confidential, and its registration access token (RFC 7592). Only their digests or
 * hashes are kept.
 */
final readonly class ClientRegisteredItself
{
    /**
     * @param non-empty-string|null $clientSecret
     * @param non-empty-string      $registrationAccessToken
     */
    public function __construct(
        public Client $client,
        public ClientRegistration $registration,
        #[\SensitiveParameter] public ?string $clientSecret,
        #[\SensitiveParameter] public string $registrationAccessToken,
    ) {
    }
}
