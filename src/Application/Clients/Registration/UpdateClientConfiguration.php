<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Clients\Registration;

use Clavia\Application\Audit\AuditContext;
use Clavia\Application\Port\DomainEvents;
use Clavia\Application\Port\PasswordHasher;
use Clavia\Application\Port\TransactionManager;
use Clavia\Domain\Audit\Actor;
use Clavia\Domain\Client\Client;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Client\Event\ClientChanged;
use Clavia\Domain\Client\Registration\ClientRegistrationRepository;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\SecretGenerator;
use Clavia\Domain\Shared\Url;

/**
 * `PUT /oauth2/register/{client_id}` (RFC 7592 §2.2): a self-registered client replaces its
 * metadata, under the same policy as at registration ({@see RegistrationMetadata}), and gets a new
 * registration access token; the old one stops working (§3).
 *
 * A `PUT` replaces: an omitted field takes its default. What is not the client's to say stays as
 * it is — its id, its type, its secret, and the operator's settings (PKCE, MFA policy, pushed
 * requests, connections).
 */
final readonly class UpdateClientConfiguration
{
    /** §2.2: read-only fields the server hands out, never taken back from a client. */
    private const array SERVER_FIELDS = [
        'registration_access_token',
        'registration_client_uri',
        'client_secret_expires_at',
        'client_id_issued_at',
    ];

    public function __construct(
        private RegisteredClients $registered,
        private RegistrationMetadata $metadata,
        private ClientRepository $clients,
        private ClientRegistrationRepository $registrations,
        private PasswordHasher $hasher,
        private SecretGenerator $secrets,
        private TransactionManager $transactions,
        private AuditContext $audit,
        private DomainEvents $events,
    ) {
    }

    /**
     * @param array<array-key, mixed> $members The request's JSON object.
     *
     * @throws RegistrationAccessTokenRejected
     * @throws RegistrationRefused
     */
    public function __invoke(
        #[\SensitiveParameter] ?string $registrationAccessToken,
        string $clientId,
        array $members,
    ): ClientConfiguration {
        $current = $this->registered->authenticate($registrationAccessToken, $clientId);
        $client = $current->client;

        if (($members['client_id'] ?? null) !== $client->id->value) {
            throw RegistrationRefused::metadata("'client_id' is required, and is this client's.");
        }
        foreach (self::SERVER_FIELDS as $field) {
            if (array_key_exists($field, $members)) {
                throw RegistrationRefused::metadata(sprintf("'%s' is the server's to set.", $field));
            }
        }
        /** @var mixed $secret */
        $secret = $members['client_secret'] ?? null;
        $hash = $client->secretHash();
        if ($secret !== null && (! is_string($secret) || $hash === null || ! $this->hasher->verify($secret, $hash))) {
            throw RegistrationRefused::metadata("'client_secret', when sent, is the client's current one.");
        }

        $metadata = $this->metadata->read($members);
        if ($metadata->type !== $client->type) {
            throw RegistrationRefused::metadata(
                "'token_endpoint_auth_method' cannot make a confidential client public, or the reverse.",
            );
        }
        $updated = self::replaced($client, $metadata);

        return $this->transactions->transactional(function () use ($current, $client, $updated): ClientConfiguration {
            $token = $this->secrets->token();
            $registration = $current->registration->rotate(Digest::of($token));
            $this->clients->save($updated);
            $this->registrations->save($registration);
            $this->audit->actAs(Actor::application($client->id));
            $this->events->dispatch(new ClientChanged($client->id, self::changed($client, $updated)));

            return new ClientConfiguration($updated, $registration, $token);
        });
    }

    /**
     * @throws RegistrationRefused
     */
    private static function replaced(Client $client, ClientMetadata $metadata): Client
    {
        try {
            return Client::register(
                $client->id,
                $metadata->name,
                $client->type,
                $metadata->authMethod,
                $client->secretHash(),
                $metadata->redirectUris,
                $metadata->grantTypes,
                $metadata->responseTypes,
                $client->createdAt,
                $metadata->postLogoutRedirectUris,
                $client->connections,
                $metadata->backChannelLogout,
                $client->requiresPkce,
                $client->mfaPolicy,
                $client->requiresPushedAuthorizationRequests,
                $metadata->requireDpop,
            );
        } catch (InvalidValue $contradiction) {
            throw RegistrationRefused::metadata($contradiction->getMessage());
        }
    }

    /**
     * What the update changed, by the Management API's field names — never to what.
     *
     * @return list<string>
     */
    private static function changed(Client $before, Client $after): array
    {
        $uris = static fn (array $list): array => array_map(static fn (Url $uri): string => $uri->value, $list);

        return array_keys(array_filter([
            'name' => $before->name !== $after->name,
            'token_endpoint_auth_method' => $before->authMethod !== $after->authMethod,
            'redirect_uris' => $uris($before->redirectUris) !== $uris($after->redirectUris),
            'grant_types' => $before->grantTypes !== $after->grantTypes,
            'response_types' => $before->responseTypes !== $after->responseTypes,
            'post_logout_redirect_uris' => $uris($before->postLogoutRedirectUris)
                !== $uris($after->postLogoutRedirectUris),
            'backchannel_logout_uri' => $before->backChannelLogout?->uri->value
                !== $after->backChannelLogout?->uri->value,
            'backchannel_logout_session_required' => ($before->backChannelLogout->sessionRequired ?? false)
                !== ($after->backChannelLogout->sessionRequired ?? false),
            'dpop_bound_access_tokens' => $before->requiresDpop !== $after->requiresDpop,
        ]));
    }
}
