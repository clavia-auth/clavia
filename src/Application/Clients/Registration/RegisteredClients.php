<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Clients\Registration;

use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Client\Registration\ClientRegistrationRepository;
use Clavia\Domain\Shared\Digest;

/**
 * Who is calling the configuration endpoint (RFC 7592 §2): the client a registration access token
 * answers for, and only when it is the one in the path. An operator's client has no registration,
 * so no token answers for it.
 */
final readonly class RegisteredClients
{
    public function __construct(
        private ClientRepository $clients,
        private ClientRegistrationRepository $registrations,
    ) {
    }

    /**
     * @throws RegistrationAccessTokenRejected
     */
    public function authenticate(
        #[\SensitiveParameter] ?string $registrationAccessToken,
        string $clientId,
    ): ClientConfiguration {
        $registration = $registrationAccessToken === null
            ? null
            : $this->registrations->findByAccessToken(Digest::of($registrationAccessToken));
        // Compared as strings: a malformed id in the path is just another client this token is not for.
        if ($registration === null || $registration->clientId->value !== $clientId) {
            throw new RegistrationAccessTokenRejected();
        }
        $client = $this->clients->find(ClientId::fromString($clientId)) ?? throw new RegistrationAccessTokenRejected();

        return new ClientConfiguration($client, $registration);
    }
}
