<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Clients;

use Clavia\Application\Port\PasswordHasher;
use Clavia\Domain\Client\Client;
use Clavia\Domain\Client\ClientAuthMethod;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Client\ClientType;
use Clavia\Domain\Client\Ownership;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\SecretGenerator;

/**
 * `POST /api/v1/clients`: register a client, generating its id and — when confidential —
 * its secret, of which only a hash is kept.
 *
 * A registration no flow could serve is refused here, where it was written, rather
 * than discovered as a broken flow far from it: {@see Client::register()} holds the rules.
 */
final readonly class RegisterClient
{
    public function __construct(
        private ClientRepository $clients,
        private PasswordHasher $hasher,
        private SecretGenerator $secrets,
        private Clock $clock,
    ) {
    }

    /**
     * @throws InvalidValue
     */
    public function __invoke(NewClient $new): ClientWithSecret
    {
        $type = ClientType::tryFrom($new->type) ?? throw new InvalidValue(
            sprintf("Unsupported client type '%s'.", $new->type),
        );
        $authMethod = $new->authMethod === null
            ? ($type === ClientType::Confidential ? ClientAuthMethod::ClientSecretBasic : ClientAuthMethod::None)
            : RegistrationValues::authMethod($new->authMethod);

        $secret = $type === ClientType::Confidential ? $this->secrets->token() : null;

        $client = Client::register(
            ClientId::generate($this->secrets, $new->firstParty ? Ownership::FirstParty : Ownership::ThirdParty),
            $new->name,
            $type,
            $authMethod,
            $secret === null ? null : $this->hasher->hash($secret),
            RegistrationValues::redirectUris($new->redirectUris),
            RegistrationValues::grantTypes($new->grantTypes),
            RegistrationValues::responseTypes($new->responseTypes),
            $this->clock->now(),
            RegistrationValues::redirectUris($new->postLogoutRedirectUris),
        );
        $this->clients->save($client);

        return new ClientWithSecret($client, $secret);
    }
}
