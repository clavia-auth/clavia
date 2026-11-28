<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Management;

use Clavia\Adapter\Primary\Http\Access\RelationshipDocument;
use Clavia\Application\Authorization\Relationships\ReadRelationships;
use Clavia\Application\Authorization\Relationships\RelationshipRefused;
use Clavia\Application\Management\ResourceServers\ReadApiRelationships;
use Clavia\Application\Port\DecisionEngineFailed;
use Clavia\Domain\Authorization\ObjectRef;
use Clavia\Domain\ResourceServer\ResourceServerId;
use Clavia\Domain\Shared\InvalidValue;
use Fig\Http\Message\StatusCodeInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `GET /api/v1/resource-servers/{resource_server_id}/authorization/relationships?object=…`
 * (docs/design/fine-grained-authorization.md §5.6): one object's relationships in the API's store, a
 * page at a time, in the Authorization API's shape.
 */
final readonly class AuthorizationRelationshipsHandler implements RequestHandlerInterface
{
    public function __construct(
        private ReadApiRelationships $read,
        private ManagementResponder $responder,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $management = ManagementRequest::of($request);
        /** @var string $object */
        $object = $management->query('object');
        /** @var mixed $size */
        $size = $management->query('page_size');
        /** @var mixed $token */
        $token = $management->query('page_token');

        try {
            $page = ($this->read)(
                ResourceServerId::fromString($management->path('resource_server_id')),
                ObjectRef::fromString($object),
                is_int($size) && $size > 0 ? $size : ReadRelationships::DEFAULT_PAGE_SIZE,
                is_string($token) ? $token : '',
            );
        } catch (InvalidValue $refusal) {
            return $this->unprocessable($refusal->getMessage());
        } catch (RelationshipRefused $refusal) {
            if ($refusal->parameter === 'page_token') {
                throw new MalformedParameter('page_token', $refusal->getMessage());
            }

            return $this->unprocessable($refusal->getMessage());
        } catch (DecisionEngineFailed) {
            return $this->responder->problem(new Problem(
                StatusCodeInterface::STATUS_SERVICE_UNAVAILABLE,
                'The decision engine is unavailable; try again later.',
            ));
        }

        $document = ['items' => array_map(RelationshipDocument::of(...), $page->tuples)];
        if ($page->next !== '') {
            $document['next_page_token'] = $page->next;
        }

        return $this->responder->json($document);
    }

    private function unprocessable(string $detail): ResponseInterface
    {
        return $this->responder->problem(new Problem(
            StatusCodeInterface::STATUS_UNPROCESSABLE_ENTITY,
            ContractViolation::REFUSED,
            [['parameter' => 'object', 'detail' => $detail]],
        ));
    }
}
