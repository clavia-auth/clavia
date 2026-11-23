<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Clients;

use Clavia\Application\Management\NotFound;
use Clavia\Application\Port\DomainEvents;
use Clavia\Domain\Authentication\MfaPolicy;
use Clavia\Domain\Client\Client;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Client\Event\ClientChanged;
use Clavia\Domain\Shared\InvalidValue;

/**
 * `PATCH /api/v1/clients/{client_id}`: the merged registration is checked as a new one
 * would be, so removing the last redirect URI of a code-flow client is refused.
 */
final readonly class UpdateClient
{
    public function __construct(
        private ClientRepository $clients,
        private BackChannelLogoutRegistration $backChannel,
        private DomainEvents $events,
    ) {
    }

    /**
     * @throws NotFound
     * @throws InvalidValue
     */
    public function __invoke(ClientId $id, ClientChanges $changes): Client
    {
        $client = $this->clients->find($id) ?? throw NotFound::of('client');

        $updated = $client->reconfigure(
            $changes->name ?? $client->name,
            $changes->redirectUris === null
                ? $client->redirectUris
                : RegistrationValues::redirectUris($changes->redirectUris),
            $changes->grantTypes === null
                ? $client->grantTypes
                : RegistrationValues::grantTypes($changes->grantTypes),
            $changes->responseTypes === null
                ? $client->responseTypes
                : RegistrationValues::responseTypes($changes->responseTypes),
            $changes->authMethod === null
                ? $client->authMethod
                : RegistrationValues::authMethod($changes->authMethod),
            $changes->postLogoutRedirectUris === null
                ? null
                : RegistrationValues::redirectUris($changes->postLogoutRedirectUris),
        );
        if ($changes->changesBackChannelLogoutUri || $changes->backChannelLogoutSessionRequired !== null) {
            $updated = $updated->withBackChannelLogout($this->backChannel->of(
                $changes->changesBackChannelLogoutUri
                    ? $changes->backChannelLogoutUri
                    : $client->backChannelLogout?->uri->value,
                $changes->backChannelLogoutSessionRequired ?? $client->backChannelLogout->sessionRequired ?? false,
            ));
        }
        if ($changes->requirePkce !== null) {
            $updated = $updated->withPkceRequired($changes->requirePkce);
        }
        if ($changes->mfaPolicy !== null) {
            $updated = $updated->requiringMfa(MfaPolicy::fromString($changes->mfaPolicy));
        }
        $this->clients->save($updated);
        $this->events->dispatch(new ClientChanged($updated->id, self::fields($changes)));

        return $updated;
    }

    /**
     * What the request set, by API field name — the trail says what changed, not to what.
     *
     * @return list<string>
     */
    private static function fields(ClientChanges $changes): array
    {
        return array_keys(array_filter([
            'name' => $changes->name !== null,
            'token_endpoint_auth_method' => $changes->authMethod !== null,
            'redirect_uris' => $changes->redirectUris !== null,
            'grant_types' => $changes->grantTypes !== null,
            'response_types' => $changes->responseTypes !== null,
            'post_logout_redirect_uris' => $changes->postLogoutRedirectUris !== null,
            'backchannel_logout_uri' => $changes->changesBackChannelLogoutUri,
            'backchannel_logout_session_required' => $changes->backChannelLogoutSessionRequired !== null,
            'require_pkce' => $changes->requirePkce !== null,
            'mfa_policy' => $changes->mfaPolicy !== null,
        ]));
    }
}
