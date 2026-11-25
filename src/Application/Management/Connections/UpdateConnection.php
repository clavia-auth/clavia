<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Connections;

use Clavia\Application\Management\NotFound;
use Clavia\Application\Port\DomainEvents;
use Clavia\Domain\Connection\Connection;
use Clavia\Domain\Connection\ConnectionRepository;
use Clavia\Domain\Connection\Event\ConnectionChanged;
use Clavia\Domain\Shared\InvalidValue;

/**
 * `PATCH /api/v1/connections/{name}`: switch a connection on or off, open it to every
 * application, rename it, or — for an OIDC connection — change its provider settings.
 *
 * Switching one off takes effect at the next sign-in: sessions established through it
 * stand until they end. A social connection whose provider has no credentials can be
 * switched on — the intent is recorded — but stays unusable until the deployment
 * configures it. Changed provider settings are discovered again; a new secret replaces
 * the old one.
 */
final readonly class UpdateConnection
{
    public function __construct(
        private ConnectionRepository $connections,
        private OidcConfiguration $oidc,
        private DomainEvents $events,
    ) {
    }

    /**
     * @param array{issuer?: string, client_id?: string, client_secret?: string, scope?: string} $oidc
     *        The OIDC settings sent; any one makes the whole configuration be checked again.
     *
     * @throws NotFound
     * @throws InvalidValue
     */
    public function __invoke(
        string $name,
        ?string $displayName,
        ?bool $isEnabled,
        ?bool $isDomainConnection,
        array $oidc = [],
        ?bool $allowSignUp = null,
        ?bool $requireVerifiedEmail = null,
        ?bool $requireProvisioning = null,
    ): Connection {
        $connection = ReadConnections::find($this->connections, $name)->switched(
            $isEnabled,
            $isDomainConnection,
            $displayName,
            $allowSignUp,
            $requireVerifiedEmail,
            $requireProvisioning,
        );

        if ($oidc !== []) {
            $current = $connection->oidc ?? throw new InvalidValue('Only an OIDC connection has OIDC settings.');
            $connection = $connection->withOidc($this->oidc->settings(
                $connection->name,
                $oidc['issuer'] ?? $current->issuer->value,
                $oidc['client_id'] ?? $current->clientId,
                $oidc['client_secret'] ?? null,
                $current->encryptedClientSecret,
                $oidc['scope'] ?? $current->scope->toString(),
            ));
        }
        $this->connections->save($connection);
        $this->events->dispatch(new ConnectionChanged($connection->name, array_merge(
            array_keys(array_filter([
                'display_name' => $displayName !== null,
                'is_enabled' => $isEnabled !== null,
                'is_domain_connection' => $isDomainConnection !== null,
                'allow_sign_up' => $allowSignUp !== null,
                'require_verified_email' => $requireVerifiedEmail !== null,
                'require_provisioning' => $requireProvisioning !== null,
            ])),
            array_map(static fn (string|int $field): string => 'oidc.' . $field, array_keys($oidc)),
        )));

        return $connection;
    }
}
