<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Scim;

use Clavia\Application\Provisioning\Groups\CreateScimGroup;
use Clavia\Application\Provisioning\Groups\ReadScimGroups;
use Clavia\Application\Provisioning\Users\AttributeTaken;
use Clavia\Application\Provisioning\Users\ReadScimUsers;
use Clavia\Domain\Provisioning\ScimFilter;
use Clavia\Domain\Provisioning\ScimFilterAttribute;
use Clavia\Domain\Provisioning\ScimGroup;
use Clavia\Domain\Provisioning\ScimGroupResource;
use Clavia\Domain\Shared\InvalidValue;
use Fig\Http\Message\RequestMethodInterface;
use Fig\Http\Message\StatusCodeInterface;
use LogicException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `/scim/v2/Groups`: `POST` creates a group (RFC 7644 §3.3), `GET` lists them with `filter` on
 * `displayName`, `externalId` or `id`, `startIndex`, `count` and `excludedAttributes` (§3.4.2), in
 * the connection of the caller's token.
 */
final readonly class ScimGroupsHandler implements RequestHandlerInterface
{
    private const int BAD_REQUEST = StatusCodeInterface::STATUS_BAD_REQUEST;

    /** @param non-empty-string $baseUrl */
    public function __construct(
        private CreateScimGroup $create,
        private ReadScimGroups $read,
        private ScimResponder $responder,
        private string $baseUrl,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        try {
            return match ($request->getMethod()) {
                RequestMethodInterface::METHOD_GET => $this->list($request),
                RequestMethodInterface::METHOD_POST => $this->create($request),
                default => throw new LogicException('Routed with a method the handler does not serve.'),
            };
        } catch (ScimRequestRejected $rejection) {
            return $this->responder->error($rejection->status, $rejection->getMessage(), $rejection->scimType);
        }
    }

    private function create(ServerRequestInterface $request): ResponseInterface
    {
        try {
            $resource = ScimGroupResource::fromJson(ScimBody::read($request));
            $created = ($this->create)(ScimRequest::caller($request), $resource);
        } catch (InvalidValue $refusal) {
            return $this->responder->error(self::BAD_REQUEST, $refusal->getMessage(), 'invalidValue');
        }
        if ($created instanceof AttributeTaken) {
            return $this->responder->error(
                StatusCodeInterface::STATUS_CONFLICT,
                sprintf("The '%s' is already another group's in this connection.", $created->attribute),
                'uniqueness',
            );
        }

        return $this->responder->json(
            ScimGroupDocument::of($created, $this->baseUrl),
            StatusCodeInterface::STATUS_CREATED,
            [
                'Location' => ScimGroupDocument::location($created->id->value, $this->baseUrl),
                'ETag' => ScimGroupDocument::etag($created),
            ],
        );
    }

    private function list(ServerRequestInterface $request): ResponseInterface
    {
        $query = ScimQuery::of($request);
        $filter = $query->filter();
        try {
            $parsed = $filter === null ? null : ScimFilter::parse($filter, ScimFilterAttribute::GROUPS);
        } catch (InvalidValue $refusal) {
            return $this->responder->error(self::BAD_REQUEST, $refusal->getMessage(), 'invalidFilter');
        }
        $page = $this->read->page(
            ScimRequest::caller($request),
            $parsed,
            $query->integer('startIndex', 1),
            $query->integer('count', ReadScimUsers::DEFAULT_COUNT),
        );
        $withMembers = ! $query->excludes('members');

        return $this->responder->json([
            'schemas' => [ScimResponder::LIST_SCHEMA],
            'totalResults' => $page->total,
            'startIndex' => $page->startIndex,
            'itemsPerPage' => count($page->groups),
            'Resources' => array_map(
                fn (ScimGroup $group): array => ScimGroupDocument::of($group, $this->baseUrl, $withMembers),
                $page->groups,
            ),
        ]);
    }
}
