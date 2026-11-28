<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Management;

use Clavia\Application\Management\ResourceServers\PageTokenRefused;
use Clavia\Application\Management\ResourceServers\ReadModelVersions;
use Clavia\Application\Port\DecisionEngineFailed;
use Clavia\Application\Port\ModelVersion;
use Clavia\Domain\ResourceServer\ResourceServerId;
use Fig\Http\Message\StatusCodeInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `GET /api/v1/resource-servers/{resource_server_id}/authorization/models`
 * (docs/design/fine-grained-authorization.md §5.6): an API's model versions, newest first, a page at a
 * time, `{items, next_page_token}` since the engine pages by token and counts nothing.
 */
final readonly class AuthorizationModelsHandler implements RequestHandlerInterface
{
    public function __construct(
        private ReadModelVersions $read,
        private ManagementResponder $responder,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $management = ManagementRequest::of($request);
        /** @var mixed $size */
        $size = $management->query('page_size');
        /** @var mixed $token */
        $token = $management->query('page_token');

        try {
            $versions = ($this->read)(
                ResourceServerId::fromString($management->path('resource_server_id')),
                is_int($size) && $size > 0 ? $size : ReadModelVersions::DEFAULT_PAGE_SIZE,
                is_string($token) ? $token : '',
            );
        } catch (PageTokenRefused $refusal) {
            throw new MalformedParameter('page_token', $refusal->getMessage());
        } catch (DecisionEngineFailed) {
            return $this->responder->problem(new Problem(
                StatusCodeInterface::STATUS_SERVICE_UNAVAILABLE,
                'The decision engine is unavailable; try again later.',
            ));
        }

        $document = ['items' => array_map(
            static fn (ModelVersion $version): array => [
                'id' => $version->id->value,
                'created_at' => ManagementViews::instant($version->id->createdAt()),
                'in_force' => $version->id->equals($versions->inForce),
                'model' => json_decode($version->json, false, 128, JSON_THROW_ON_ERROR),
            ],
            $versions->page->models,
        )];
        if ($versions->page->next !== '') {
            $document['next_page_token'] = $versions->page->next;
        }

        return $this->responder->json($document);
    }
}
