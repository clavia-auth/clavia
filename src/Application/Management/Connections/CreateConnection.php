<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Connections;

use Clavia\Application\Port\DomainEvents;
use Clavia\Domain\Connection\Connection;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Connection\ConnectionRepository;
use Clavia\Domain\Connection\ConnectionStrategy;
use Clavia\Domain\Connection\Event\ConnectionCreated;
use Clavia\Domain\Shared\AlreadyExists;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\InvalidValue;

/**
 * `POST /api/v1/connections`: create a pool, or register an OpenID Connect provider.
 *
 * The name is permanent: accounts, sessions and identities record it, and for an OIDC
 * connection it is part of the callback URL registered at the provider
 * (`{issuer}/auth/social/{name}/callback`). A provider is discovered now; its client
 * secret is stored encrypted and never returned. Social connections are built in: they
 * are switched, not created.
 */
final readonly class CreateConnection
{
    public function __construct(
        private ConnectionRepository $connections,
        private OidcConfiguration $oidc,
        private SamlConfiguration $saml,
        private Clock $clock,
        private DomainEvents $events,
    ) {
    }

    /**
     * @throws InvalidValue
     * @throws AlreadyExists
     * @throws SamlMetadataRefused
     */
    public function __invoke(NewConnection $new): Connection
    {
        $name = ConnectionName::fromString($new->name);
        $strategy = ConnectionStrategy::tryFrom($new->strategy)
            ?? throw new InvalidValue(sprintf("Unknown connection strategy '%s'.", $new->strategy));
        if ($this->connections->find($name) !== null) {
            throw new AlreadyExists('A connection with this name already exists.');
        }

        if (($new->saml !== null) !== ($strategy === ConnectionStrategy::Saml)) {
            throw new InvalidValue('A SAML connection, and only one, has saml settings.');
        }
        if ($strategy === ConnectionStrategy::Saml && $new->hasOidcSettings()) {
            throw new InvalidValue('A SAML connection has no OIDC settings.');
        }
        if (($new->allowSignUp || $new->requireVerifiedEmail) && $strategy !== ConnectionStrategy::Database) {
            throw new InvalidValue('Only a database connection takes sign-ups or requires a verified address.');
        }
        $connection = match ($strategy) {
            ConnectionStrategy::Social => throw new InvalidValue(
                'Social connections are built in: switch them on or off. Register any other OpenID Connect '
                . "provider as an 'oidc' connection.",
            ),
            ConnectionStrategy::Passwordless => throw new InvalidValue(
                "Passwordless sign-in is built in, as the 'email' connection: switch it on or off.",
            ),
            ConnectionStrategy::Database => $new->hasOidcSettings()
                ? throw new InvalidValue('A database connection has no OIDC settings.')
                : Connection::pool(
                    $name,
                    $new->displayName,
                    $new->isEnabled,
                    $new->isDomainConnection,
                    $this->clock->now(),
                    $new->allowSignUp,
                    $new->requireVerifiedEmail,
                ),
            ConnectionStrategy::Oidc => Connection::openIdProvider(
                $name,
                $new->displayName,
                $this->oidc->settings(
                    $name,
                    $new->oidcIssuer ?? '',
                    $new->oidcClientId ?? '',
                    $new->oidcClientSecret,
                    null,
                    $new->oidcScope,
                ),
                $new->isEnabled,
                $new->isDomainConnection,
                $this->clock->now(),
            ),
            ConnectionStrategy::Saml => Connection::samlProvider(
                $name,
                $new->displayName,
                $this->saml->settings($new->saml ?? throw new \LogicException('Checked above.')),
                $new->isEnabled,
                $new->isDomainConnection,
                $this->clock->now(),
            ),
        };
        if ($new->requireProvisioning) {
            // Refused by the connection itself for anything but an enterprise one.
            $connection = $connection->switched(null, null, null, requiresProvisioning: true);
        }
        $this->connections->add($connection);
        $this->events->dispatch(new ConnectionCreated($connection));

        return $connection;
    }
}
