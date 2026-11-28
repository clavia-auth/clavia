<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\ResourceServers;

use Clavia\Application\Management\Conflict;
use Clavia\Application\Management\NotFound;
use Clavia\Application\Port\DecisionEngine;
use Clavia\Application\Port\DecisionEngineFailed;
use Clavia\Domain\ResourceServer\ResourceServerId;

/**
 * `GET /api/v1/resource-servers/{id}/authorization/models` (docs/design/fine-grained-authorization.md
 * §5.6): the versions of the API's model its store holds, newest first, a page at a time, and the one
 * in force. Read from the engine, which keeps them all; Clavia keeps only the one in force.
 */
final readonly class ReadModelVersions
{
    /** A page when none is asked for: a model can be 256 KiB. */
    public const int DEFAULT_PAGE_SIZE = 10;

    /** The largest page. */
    public const int MAX_PAGE_SIZE = 20;

    public function __construct(
        private AuthorizedApi $apis,
        private DecisionEngine $engine,
    ) {
    }

    /**
     * @param positive-int $pageSize At most {@see self::MAX_PAGE_SIZE}.
     * @param string $pageToken The token the previous page gave, '' for the first.
     *
     * @throws NotFound
     * @throws Conflict
     * @throws PageTokenRefused
     * @throws DecisionEngineFailed When the engine gives no answer.
     */
    public function __invoke(ResourceServerId $id, int $pageSize, string $pageToken = ''): ModelVersions
    {
        [, $settings] = $this->apis->of($id);

        try {
            $page = $this->engine->readModels($settings->store, min($pageSize, self::MAX_PAGE_SIZE), $pageToken);
        } catch (DecisionEngineFailed $failed) {
            throw $failed->refusal !== null && $pageToken !== '' ? new PageTokenRefused() : $failed;
        }

        return new ModelVersions($settings->modelId, $page);
    }
}
