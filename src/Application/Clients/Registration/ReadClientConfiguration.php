<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Clients\Registration;

/**
 * `GET /oauth2/register/{client_id}` (RFC 7592 §2.1): a self-registered client reads its
 * configuration. The registration access token is not rotated: a client that lost the answer
 * would lock itself out.
 */
final readonly class ReadClientConfiguration
{
    public function __construct(private RegisteredClients $registered)
    {
    }

    /**
     * @throws RegistrationAccessTokenRejected
     */
    public function __invoke(
        #[\SensitiveParameter] ?string $registrationAccessToken,
        string $clientId,
    ): ClientConfiguration {
        return $this->registered->authenticate($registrationAccessToken, $clientId);
    }
}
