<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Audit\Trail;

use Clavia\Application\Audit\Audit;
use Clavia\Application\Event\EventSubscriber;
use Clavia\Domain\Audit\AuditEventType;
use Clavia\Domain\Audit\AuditTarget;
use Clavia\Domain\Client\Event\ClientChanged;
use Clavia\Domain\Client\Event\ClientConnectionsChanged;
use Clavia\Domain\Client\Event\ClientDeleted;
use Clavia\Domain\Client\Event\ClientRegistered;
use Clavia\Domain\Client\Event\ClientSecretRotated;
use Clavia\Domain\Client\GrantType;
use Clavia\Domain\Client\Registration\Event\InitialAccessTokenIssued;
use Clavia\Domain\Client\Registration\Event\InitialAccessTokenRevoked;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Connection\Event\ConnectionChanged;
use Clavia\Domain\Connection\Event\ConnectionCreated;
use Clavia\Domain\Connection\Event\ConnectionDeleted;
use Clavia\Domain\Connection\Saml\Event\ServiceProviderKeysGenerated;
use Clavia\Domain\Connection\Saml\Event\ServiceProviderKeysRotated;
use Clavia\Domain\Oidc\Event\SigningKeyCreated;
use Clavia\Domain\Oidc\Event\SigningKeyRotated;
use Clavia\Domain\ResourceServer\Event\ClientAccessGranted;
use Clavia\Domain\ResourceServer\Event\ResourceServerChanged;
use Clavia\Domain\ResourceServer\Event\ResourceServerDeleted;
use Clavia\Domain\ResourceServer\Event\ResourceServerRegistered;
use Clavia\Domain\Webhook\Event\WebhookChanged;
use Clavia\Domain\Webhook\Event\WebhookCreated;
use Clavia\Domain\Webhook\Event\WebhookDeleted;
use Clavia\Domain\Webhook\Event\WebhookDisabled;
use Clavia\Domain\Webhook\Event\WebhookSecretRotated;
use Clavia\Domain\Webhook\Event\WebhookTested;
use Clavia\Domain\Webhook\WebhookEndpoint;

/**
 * Applications, APIs, client grants, connections, signing keys and initial access tokens — in the
 * audit trail.
 *
 * The actor is the request's caller: an operator through the dashboard, a machine client
 * holding a Management API token, or the system at the console. A change lists what it
 * touched, never the values: a secret, a redirect URI or a provider's client secret
 * never reaches the trail.
 */
final readonly class ConfigurationTrail implements EventSubscriber
{
    public function __construct(private Audit $audit)
    {
    }

    #[\Override]
    public function subscriptions(): array
    {
        return [
            ClientRegistered::class => $this->clientRegistered(...),
            ClientChanged::class => $this->clientChanged(...),
            ClientConnectionsChanged::class => $this->clientConnectionsChanged(...),
            ClientSecretRotated::class => $this->clientSecretRotated(...),
            ClientDeleted::class => $this->clientDeleted(...),
            ResourceServerRegistered::class => $this->resourceServerRegistered(...),
            ResourceServerChanged::class => $this->resourceServerChanged(...),
            ResourceServerDeleted::class => $this->resourceServerDeleted(...),
            ClientAccessGranted::class => $this->clientAccessGranted(...),
            ConnectionCreated::class => $this->connectionCreated(...),
            ConnectionChanged::class => $this->connectionChanged(...),
            ConnectionDeleted::class => $this->connectionDeleted(...),
            SigningKeyCreated::class => $this->signingKeyCreated(...),
            SigningKeyRotated::class => $this->signingKeyRotated(...),
            ServiceProviderKeysGenerated::class => $this->serviceProviderKeysGenerated(...),
            ServiceProviderKeysRotated::class => $this->serviceProviderKeysRotated(...),
            InitialAccessTokenIssued::class => $this->initialAccessTokenIssued(...),
            InitialAccessTokenRevoked::class => $this->initialAccessTokenRevoked(...),
            WebhookCreated::class => $this->webhookCreated(...),
            WebhookChanged::class => $this->webhookChanged(...),
            WebhookDeleted::class => $this->webhookDeleted(...),
            WebhookSecretRotated::class => $this->webhookSecretRotated(...),
            WebhookTested::class => $this->webhookTested(...),
            WebhookDisabled::class => $this->webhookDisabled(...),
        ];
    }

    private function clientRegistered(ClientRegistered $event): void
    {
        $client = $event->client;
        $detail = [
            'name' => $client->name,
            'client_type' => $client->type->value,
            'first_party' => $client->isFirstParty(),
            'grant_types' => array_map(static fn (GrantType $grant): string => $grant->value, $client->grantTypes),
        ];
        if ($event->registeredWith !== null) {
            // A client that registered itself (RFC 7591): which initial access token let it in.
            $detail['registered_with'] = $event->registeredWith->value;
        }
        $this->audit->record(AuditEventType::ClientCreated, AuditTarget::client($client->id), $detail);
    }

    private function clientChanged(ClientChanged $event): void
    {
        $this->audit->record(AuditEventType::ClientUpdated, AuditTarget::client($event->clientId), [
            'fields' => $event->changed,
        ]);
    }

    private function clientConnectionsChanged(ClientConnectionsChanged $event): void
    {
        $this->audit->record(AuditEventType::ClientUpdated, AuditTarget::client($event->clientId), [
            'fields' => ['connections'],
            'connections' => array_map(static fn (ConnectionName $name): string => $name->value, $event->connections),
        ]);
    }

    private function clientSecretRotated(ClientSecretRotated $event): void
    {
        $this->audit->record(AuditEventType::ClientSecretRotated, AuditTarget::client($event->clientId));
    }

    private function clientDeleted(ClientDeleted $event): void
    {
        $this->audit->record(AuditEventType::ClientDeleted, AuditTarget::client($event->client->id), [
            'name' => $event->client->name,
        ]);
    }

    private function resourceServerRegistered(ResourceServerRegistered $event): void
    {
        $api = $event->resourceServer;
        $this->audit->record(AuditEventType::ResourceServerCreated, AuditTarget::resourceServer($api->id), [
            'identifier' => $api->identifier->value,
        ]);
    }

    private function resourceServerChanged(ResourceServerChanged $event): void
    {
        $this->audit->record(
            AuditEventType::ResourceServerUpdated,
            AuditTarget::resourceServer($event->resourceServerId),
            ['fields' => $event->changed],
        );
    }

    private function resourceServerDeleted(ResourceServerDeleted $event): void
    {
        $api = $event->resourceServer;
        $this->audit->record(AuditEventType::ResourceServerDeleted, AuditTarget::resourceServer($api->id), [
            'identifier' => $api->identifier->value,
        ]);
    }

    private function clientAccessGranted(ClientAccessGranted $event): void
    {
        $this->audit->record(AuditEventType::ClientGranted, AuditTarget::client($event->grant->clientId), [
            'audience' => $event->audience->value,
            'scope' => $event->grant->scopes->toString(),
        ]);
    }

    private function connectionCreated(ConnectionCreated $event): void
    {
        $connection = $event->connection;
        $this->audit->record(AuditEventType::ConnectionCreated, AuditTarget::connection($connection->name), [
            'strategy' => $connection->strategy->value,
        ]);
    }

    private function connectionChanged(ConnectionChanged $event): void
    {
        $this->audit->record(AuditEventType::ConnectionUpdated, AuditTarget::connection($event->name), [
            'fields' => $event->changed,
        ]);
    }

    private function connectionDeleted(ConnectionDeleted $event): void
    {
        $this->audit->record(AuditEventType::ConnectionDeleted, AuditTarget::connection($event->name));
    }

    private function signingKeyCreated(SigningKeyCreated $event): void
    {
        $this->audit->record(AuditEventType::SigningKeyCreated, AuditTarget::signingKey($event->key->kid()), [
            'algorithm' => $event->key->algorithm()->value,
        ]);
    }

    private function signingKeyRotated(SigningKeyRotated $event): void
    {
        $this->audit->record(AuditEventType::SigningKeyRotated, AuditTarget::signingKey($event->active->kid()), [
            'algorithm' => $event->active->algorithm()->value,
            'retired_kid' => $event->retired?->kid(),
        ]);
    }

    private function serviceProviderKeysGenerated(ServiceProviderKeysGenerated $event): void
    {
        $this->audit->record(AuditEventType::SamlKeyGenerated, AuditTarget::samlKey($event->signing->kid), [
            'encryption_kid' => $event->encryption->kid,
        ]);
    }

    private function serviceProviderKeysRotated(ServiceProviderKeysRotated $event): void
    {
        $this->audit->record(AuditEventType::SamlKeyRotated, AuditTarget::samlKey($event->signing->kid), [
            'step' => $event->promoted ? 'promoted' : 'introduced',
            'encryption_kid' => $event->encryption->kid,
        ]);
    }

    private function initialAccessTokenIssued(InitialAccessTokenIssued $event): void
    {
        $token = $event->token;
        $this->audit->record(AuditEventType::InitialAccessTokenIssued, AuditTarget::initialAccessToken($token->id), [
            'description' => $token->description,
            'max_uses' => $token->maxUses,
        ]);
    }

    private function initialAccessTokenRevoked(InitialAccessTokenRevoked $event): void
    {
        $this->audit->record(
            AuditEventType::InitialAccessTokenRevoked,
            AuditTarget::initialAccessToken($event->token->id),
            ['uses' => $event->token->uses],
        );
    }

    /** The host only, not the path, which can carry a receiver's own token; never the secret. */
    private function webhookCreated(WebhookCreated $event): void
    {
        $endpoint = $event->endpoint;
        $this->audit->record(AuditEventType::WebhookCreated, AuditTarget::webhook($endpoint->id), [
            'host' => $endpoint->url->host(),
            'events' => $endpoint->events->toStrings(),
        ]);
    }

    private function webhookChanged(WebhookChanged $event): void
    {
        $this->audit->record(AuditEventType::WebhookUpdated, AuditTarget::webhook($event->id), [
            'fields' => $event->changed,
        ]);
    }

    private function webhookDeleted(WebhookDeleted $event): void
    {
        $this->audit->record(AuditEventType::WebhookDeleted, AuditTarget::webhook($event->endpoint->id), [
            'host' => $event->endpoint->url->host(),
        ]);
    }

    private function webhookSecretRotated(WebhookSecretRotated $event): void
    {
        $this->audit->record(AuditEventType::WebhookSecretRotated, AuditTarget::webhook($event->id));
    }

    /** The outbox sends this one to its target alone. */
    private function webhookTested(WebhookTested $event): void
    {
        $this->audit->record(AuditEventType::WebhookTested, AuditTarget::webhook($event->id));
    }

    private function webhookDisabled(WebhookDisabled $event): void
    {
        $this->audit->record(AuditEventType::WebhookDisabled, AuditTarget::webhook($event->id), [
            'reason' => 'failing',
            'days' => WebhookEndpoint::DEAD_AFTER_DAYS,
        ]);
    }
}
