<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Scim;

use LogicException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `GET /scim/v2/ResourceTypes[/{id}]` and `GET /scim/v2/Schemas[/{id}]` (RFC 7644 §4, RFC 7643
 * §6, §7): the resource types and schemas this service provider supports, listed or one by its id.
 *
 * Built from what exists, and nothing ahead of it ({@see ScimCatalogue}): `Group` and its schema join
 * with the slice that serves `/Groups` (docs/design/scim-provisioning.md §9). An id not listed is
 * `404`.
 */
final readonly class ScimCatalogueHandler implements RequestHandlerInterface
{
    /**
     * @param array{ResourceTypes: list<array<string, mixed>>, Schemas: list<array<string, mixed>>} $catalogues
     *        Each catalogue's resources, every one with its `id`.
     */
    public function __construct(
        private ScimResponder $responder,
        private array $catalogues,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $resources = match ($request->getAttribute('catalogue')) {
            'ResourceTypes' => $this->catalogues['ResourceTypes'],
            'Schemas' => $this->catalogues['Schemas'],
            default => throw new LogicException('Routed without a catalogue the handler serves.'),
        };
        /** @var mixed $id */
        $id = $request->getAttribute('id');
        if (! is_string($id)) {
            return $this->responder->listOf($resources);
        }
        foreach ($resources as $resource) {
            if (($resource['id'] ?? null) === $id) {
                return $this->responder->json($resource);
            }
        }

        return $this->responder->notFound();
    }
}
