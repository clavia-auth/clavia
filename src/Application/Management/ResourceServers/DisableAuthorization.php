<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\ResourceServers;

use Clavia\Application\Management\NotFound;
use Clavia\Application\Port\DecisionEngine;
use Clavia\Application\Port\DecisionEngineFailed;
use Clavia\Application\Port\DomainEvents;
use Clavia\Application\Port\TransactionManager;
use Clavia\Domain\Authorization\Event\AuthorizationDisabled;
use Clavia\Domain\ResourceServer\ResourceServerId;
use Clavia\Domain\ResourceServer\ResourceServerRepository;

/**
 * `DELETE /api/v1/resource-servers/{resource_server_id}/authorization`: fine-grained authorization
 * switched off for an API (docs/design/fine-grained-authorization.md §5.1).
 *
 * Switched off, the store and its relationships are kept, so switching it on again brings them back.
 * Confirmed (`?confirm=delete`), the store is deleted with every relationship in it, and Clavia
 * forgets it, in the transaction that forgets it: OpenFGA's deletion is soft, and a store whose id
 * is still known would still answer. An engine that gives no answer leaves everything as it was.
 */
final readonly class DisableAuthorization
{
    public function __construct(
        private ResourceServerRepository $resourceServers,
        private DecisionEngine $engine,
        private TransactionManager $transactions,
        private DomainEvents $events,
    ) {
    }

    /**
     * @throws NotFound When the API does not exist, or has no fine-grained authorization to switch off.
     * @throws DecisionEngineFailed When the store is to be deleted and the engine gives no answer.
     */
    public function __invoke(ResourceServerId $id, bool $deleteStore): void
    {
        $api = $this->resourceServers->find($id) ?? throw NotFound::of('API');
        $settings = $api->authorization ?? throw NotFound::of('fine-grained authorization on this API');

        if (! $deleteStore) {
            if (! $settings->enabled) {
                return;
            }
            $this->transactions->transactional(function () use ($api, $settings): void {
                $this->resourceServers->save($api->withAuthorization($settings->disabled()));
                $this->events->dispatch(new AuthorizationDisabled($api->id, storeDeleted: false));
            });

            return;
        }

        $this->transactions->transactional(function () use ($api, $settings): void {
            $this->resourceServers->save($api->withoutAuthorization());
            $this->events->dispatch(new AuthorizationDisabled($api->id, storeDeleted: true));
            // Last, so a failure rolls the rest back.
            $this->engine->deleteStore($settings->store);
        });
    }
}
