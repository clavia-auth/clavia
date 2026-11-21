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
use Clavia\Domain\Connection\BuiltInConnection;
use Clavia\Domain\Connection\ConnectionRepository;
use Clavia\Domain\Identity\ExternalIdentityRepository;
use Clavia\Domain\Identity\UserRepository;

/**
 * `DELETE /api/v1/connections/{name}`: delete a pool or an OpenID Connect provider that
 * nothing depends on any more.
 *
 * Refused while accounts belong to it or identities are linked through it: those are
 * people's ways in, and deleting them as a side effect of removing a row is not what
 * anyone asked for. Built-in connections — the social ones and the default pool — are
 * switched off rather than deleted. Applications that enabled it stop listing it.
 */
final readonly class DeleteConnection
{
    public function __construct(
        private ConnectionRepository $connections,
        private UserRepository $users,
        private ExternalIdentityRepository $identities,
    ) {
    }

    /**
     * @throws NotFound
     * @throws BuiltInConnection
     * @throws Conflict When accounts or identities depend on it.
     */
    public function __invoke(string $name): void
    {
        $connection = ReadConnections::find($this->connections, $name);
        $connection->assertDeletable();

        $accounts = $this->users->countIn($connection->name);
        $identities = $this->identities->countThrough($connection->name);
        if ($accounts > 0 || $identities > 0) {
            throw new Conflict(sprintf(
                '%d %s to this connection and %d %s linked through it. Delete or move them first.',
                $accounts,
                $accounts === 1 ? 'account belongs' : 'accounts belong',
                $identities,
                $identities === 1 ? 'identity is' : 'identities are',
            ));
        }

        $this->connections->delete($connection->name);
    }
}
