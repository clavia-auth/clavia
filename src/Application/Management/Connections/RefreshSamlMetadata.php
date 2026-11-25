<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Connections;

use Clavia\Application\Management\Conflict;
use Clavia\Application\Management\NotFound;
use Clavia\Application\Port\DomainEvents;
use Clavia\Domain\Connection\Connection;
use Clavia\Domain\Connection\ConnectionRepository;
use Clavia\Domain\Connection\Event\ConnectionChanged;

/**
 * `POST /api/v1/connections/{name}/refresh-metadata` (docs/design/saml-connections.md §5.2): read a
 * SAML connection's metadata URL again, for a certificate the identity provider rolled over. Only on
 * demand: a refresh at every sign-in would put the identity provider's metadata host in its path.
 */
final readonly class RefreshSamlMetadata
{
    public function __construct(
        private ConnectionRepository $connections,
        private SamlConfiguration $configuration,
        private DomainEvents $events,
    ) {
    }

    /**
     * @throws NotFound
     * @throws Conflict Not a SAML connection, or one registered from a document.
     * @throws SamlMetadataRefused
     */
    public function __invoke(string $name): Connection
    {
        $connection = ReadConnections::find($this->connections, $name);
        $saml = $connection->saml ?? throw new Conflict('Only a SAML connection has metadata to refresh.');
        if ($saml->metadataUrl === null) {
            throw new Conflict(
                'This connection was registered from a metadata document: there is no URL to read again.',
            );
        }
        $refreshed = $connection->withSaml($this->configuration->refreshed($saml));
        $this->connections->save($refreshed);
        $this->events->dispatch(new ConnectionChanged($refreshed->name, ['saml.metadata']));

        return $refreshed;
    }
}
