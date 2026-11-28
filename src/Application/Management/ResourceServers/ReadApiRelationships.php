<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\ResourceServers;

use Clavia\Application\Authorization\Relationships\ReadRelationships;
use Clavia\Application\Authorization\Relationships\RelationshipRefused;
use Clavia\Application\Management\Conflict;
use Clavia\Application\Management\NotFound;
use Clavia\Application\Port\DecisionEngineFailed;
use Clavia\Application\Port\TuplePage;
use Clavia\Domain\Authorization\ObjectRef;
use Clavia\Domain\ResourceServer\ResourceServerId;

/**
 * `GET /api/v1/resource-servers/{id}/authorization/relationships?object=…`
 * (docs/design/fine-grained-authorization.md §5.6): the Authorization API's read of one object's
 * relationships, for an operator, from the store of the API they name. Clavia's own types are not read
 * here either: who holds a role is the Roles section's to tell.
 */
final readonly class ReadApiRelationships
{
    public function __construct(
        private AuthorizedApi $apis,
        private ReadRelationships $read,
    ) {
    }

    /**
     * @param positive-int $pageSize At most 100.
     *
     * @throws NotFound
     * @throws Conflict
     * @throws RelationshipRefused A reserved or unknown type, or a page token the engine does not take.
     * @throws DecisionEngineFailed When the engine gives no answer.
     */
    public function __invoke(ResourceServerId $id, ObjectRef $object, int $pageSize, string $pageToken = ''): TuplePage
    {
        [, $settings] = $this->apis->of($id);

        return $this->read->of($settings, $object, $pageSize, $pageToken);
    }
}
