<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authorization\Feed;

use Clavia\Application\Management\NotFound;
use Clavia\Application\Port\DecisionEngineFailed;
use Clavia\Domain\Authorization\FeedSubject;
use Clavia\Domain\ResourceServer\ResourceServerId;
use Clavia\Domain\ResourceServer\ResourceServerRepository;
use Clavia\Domain\Shared\Audience;
use Clavia\Domain\Shared\InvalidValue;

/**
 * `bin/clavia fga:resync <api>` (docs/design/fine-grained-authorization.md §5.4): the repair when an
 * API's store and Clavia have drifted (the feed off for a while, a store restored from a backup). The
 * members of every role are worked out from Clavia and only the difference is written, at once, past
 * the outbox.
 */
final readonly class ResyncStore
{
    public function __construct(
        private ResourceServerRepository $resourceServers,
        private StoreReconciler $reconciler,
        private bool $available,
    ) {
    }

    /**
     * @param string $api The API's id (`rs_…`) or its identifier, the audience its tokens name.
     *
     * @throws NotFound When no such API has fine-grained authorization set up.
     * @throws FineGrainedAuthorizationOff When this server names no decision engine.
     * @throws DecisionEngineFailed When the engine gives no answer, or refuses a write.
     */
    public function __invoke(string $api): Reconciled
    {
        if (! $this->available) {
            throw new FineGrainedAuthorizationOff();
        }
        $found = null;
        try {
            $found = $this->resourceServers->find(ResourceServerId::fromString($api));
        } catch (InvalidValue) {
            try {
                $found = $this->resourceServers->findByIdentifier(Audience::fromString($api));
            } catch (InvalidValue) {
                // Neither an id nor an identifier: not found.
            }
        }
        if ($found === null || $found->authorization === null) {
            throw NotFound::of('API with fine-grained authorization');
        }

        return $this->reconciler->reconcile($found, FeedSubject::everyRole());
    }
}
