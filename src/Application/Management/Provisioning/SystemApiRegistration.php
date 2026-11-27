<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Provisioning;

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
 * Register, or bring up to date, an API this server itself serves: the Management API, the
 * Authorization API.
 *
 * Idempotent in the useful direction: the permissions are made exactly the code's, so one added by
 * an upgrade arrives and one removed goes. Marked as a system API, which is what stops it from being
 * deleted or having its permissions edited over HTTP. An operator's rename is kept.
 */
final readonly class SystemApiRegistration
{
    public function __construct(
        private ResourceServerRepository $resourceServers,
        private TransactionManager $transactions,
        private SecretGenerator $secrets,
        private Clock $clock,
        private DomainEvents $events,
    ) {
    }

    /**
     * @param list<Permission> $permissions
     */
    public function register(Audience $identifier, string $name, array $permissions): ResourceServer
    {
        /** @var ResourceServer */
        return $this->transactions->transactional(function () use ($identifier, $name, $permissions): ResourceServer {
            $existing = $this->resourceServers->findByIdentifier($identifier);
            $resourceServer = $existing === null
                ? ResourceServer::register(
                    ResourceServerId::generate($this->secrets),
                    $identifier,
                    $name,
                    $permissions,
                    $this->clock->now(),
                    isSystem: true,
                    enforcePolicies: true,
                )
                : $existing->asSystem($existing->name === '' ? $name : $existing->name, $permissions);

            $this->resourceServers->save($resourceServer);
            $this->events->dispatch($existing === null
                ? new ResourceServerRegistered($resourceServer)
                : new ResourceServerChanged($resourceServer->id, ['permissions']));

            return $resourceServer;
        });
    }
}
