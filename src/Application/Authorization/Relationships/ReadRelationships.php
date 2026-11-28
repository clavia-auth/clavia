<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authorization\Relationships;

use Clavia\Application\Authorization\SpeaksForNoApi;
use Clavia\Application\Authorization\SpokenForApi;
use Clavia\Application\Port\DecisionEngine;
use Clavia\Application\Port\DecisionEngineFailed;
use Clavia\Application\Port\TuplePage;
use Clavia\Domain\Authorization\ObjectRef;
use Clavia\Domain\Authorization\ReservedType;
use Clavia\Domain\Client\ClientId;

/**
 * `GET /access/v1/relationships?object=…` (docs/design/fine-grained-authorization.md §5.3): the
 * relationships written on one of the API's own objects, a page at a time, as the engine returns them.
 * Clavia's types are not read here: who holds a role is Clavia's to tell, not the engine's.
 */
final readonly class ReadRelationships
{
    /** A page when none is asked for. */
    public const int DEFAULT_PAGE_SIZE = 50;

    public function __construct(
        private SpokenForApi $apis,
        private DecisionEngine $engine,
    ) {
    }

    /**
     * @param positive-int $pageSize At most 100.
     * @param string $pageToken The token the previous page gave, '' for the first.
     *
     * @throws SpeaksForNoApi
     * @throws RelationshipRefused A reserved or unknown type, or a page token the engine does not take.
     * @throws DecisionEngineFailed When the engine gives no answer.
     */
    public function __invoke(ClientId $caller, ObjectRef $object, int $pageSize, string $pageToken = ''): TuplePage
    {
        [, $settings] = $this->apis->of($caller);
        if (ReservedType::of($object->type) !== null) {
            throw RelationshipRefused::reservedType(parameter: 'object');
        }
        if (! $settings->model->declares($object->type)) {
            throw RelationshipRefused::unknownType(parameter: 'object');
        }

        try {
            return $this->engine->readPage($settings->store, $object, $pageSize, $pageToken);
        } catch (DecisionEngineFailed $failed) {
            if ($failed->refusal === null) {
                throw $failed;
            }
            throw $pageToken === ''
                ? RelationshipRefused::byEngine($failed->refusal)
                : RelationshipRefused::pageToken();
        }
    }
}
