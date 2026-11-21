<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Provisioning;

use Clavia\Application\Management\ManagementPermission;
use Clavia\Application\Port\DomainEvents;
use Clavia\Application\Port\TransactionManager;
use Clavia\Domain\ResourceServer\Event\ResourceServerChanged;
use Clavia\Domain\ResourceServer\Event\ResourceServerRegistered;
use Clavia\Domain\ResourceServer\Permission;
use Clavia\Domain\ResourceServer\ResourceServer;
use Clavia\Domain\ResourceServer\ResourceServerId;
use Clavia\Domain\ResourceServer\ResourceServerRepository;
use Clavia\Domain\Shared\Audience;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\SecretGenerator;

/**
 * Register — or bring up to date — the Management API's own registration:
 * `clavia management-api:register`.
 *
 * A bootstrap problem, so a shell operation: the API has to exist before a token for it
 * can be issued. Idempotent in the useful direction: the permissions are made exactly
 * {@see ManagementPermission}'s, so one added by an upgrade arrives and one removed goes.
 * Marked as a system API, which is what stops it from being deleted or having its
 * permissions edited over HTTP.
 */
final readonly class RegisterManagementApi
{
    public const string NAME = 'Clavia Management API';

    /**
     * @param Audience $identifier The Management API's identifier: `CLAVIA_MANAGEMENT_API_IDENTIFIER`,
     *                             or `https://management.{domain}/api/v1/` by default.
     */
    public function __construct(
        private ResourceServerRepository $resourceServers,
        private TransactionManager $transactions,
        private SecretGenerator $secrets,
        private Clock $clock,
        private Audience $identifier,
        private DomainEvents $events,
    ) {
    }

    public function __invoke(): ResourceServer
    {
        /** @var ResourceServer */
        return $this->transactions->transactional(function (): ResourceServer {
            $permissions = array_map(
                static fn (ManagementPermission $permission): Permission => Permission::of(
                    $permission->value,
                    $permission->description(),
                ),
                ManagementPermission::cases(),
            );

            $existing = $this->resourceServers->findByIdentifier($this->identifier);
            $resourceServer = $existing === null
                ? ResourceServer::register(
                    ResourceServerId::generate($this->secrets),
                    $this->identifier,
                    self::NAME,
                    $permissions,
                    $this->clock->now(),
                    isSystem: true,
                    enforcePolicies: true,
                )
                // An operator's rename is kept; the permissions are the code's.
                : $existing->asSystem($existing->name === '' ? self::NAME : $existing->name, $permissions);

            $this->resourceServers->save($resourceServer);
            $this->events->dispatch($existing === null
                ? new ResourceServerRegistered($resourceServer)
                : new ResourceServerChanged($resourceServer->id, ['permissions']));

            return $resourceServer;
        });
    }
}
