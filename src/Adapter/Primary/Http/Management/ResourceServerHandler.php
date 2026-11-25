<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Management;

use Clavia\Application\Management\ResourceServers\DeleteResourceServer;
use Clavia\Application\Management\ResourceServers\ReadResourceServers;
use Clavia\Application\Management\ResourceServers\UpdateResourceServer;
use Clavia\Domain\Claims\ClaimMapping;
use Clavia\Domain\Claims\ClaimMappings;
use Clavia\Domain\Claims\ClaimName;
use Clavia\Domain\Claims\ClaimSource;
use Clavia\Domain\ResourceServer\ResourceServerId;
use Clavia\Domain\Shared\InvalidValue;
use Fig\Http\Message\StatusCodeInterface;
use LogicException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `/api/v1/resource-servers/{resource_server_id}`: `GET` (`getResourceServer`),
 * `PATCH` (`updateResourceServer`), `DELETE` (`deleteResourceServer`).
 */
final readonly class ResourceServerHandler implements RequestHandlerInterface
{
    public function __construct(
        private ReadResourceServers $read,
        private UpdateResourceServer $update,
        private DeleteResourceServer $delete,
        private ManagementResponder $responder,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $management = ManagementRequest::of($request);
        $id = ResourceServerId::fromString($management->path('resource_server_id'));

        switch ($request->getMethod()) {
            case 'GET':
                return $this->responder->json(ManagementViews::resourceServer($this->read->one($id)));
            case 'PATCH':
                $claims = self::claims($management->body);
                if ($claims instanceof Problem) {
                    return $this->responder->problem($claims);
                }
                $api = ($this->update)(
                    $id,
                    $management->body->string('name'),
                    ResourceServerFields::permissions($management->body),
                    $management->body->bool('enforce_policies'),
                    $management->body->bool('allow_skipping_consent'),
                    $management->body->string('access_token_format'),
                    $management->body->string('mfa_policy'),
                    $claims,
                );

                return $this->responder->json(ManagementViews::resourceServer($api));
            case 'DELETE':
                ($this->delete)($id);

                return $this->responder->noContent();
            default:
                throw new LogicException('Routed with a method the handler does not serve.');
        }
    }

    /**
     * The `claims` of the body as mappings; null when absent; a problem pointing at each entry
     * the domain refuses (`/claims/2`), or at `/claims` for the list as a whole.
     */
    private static function claims(JsonObject $body): ClaimMappings|Problem|null
    {
        $entries = $body->objects('claims');
        if ($entries === null) {
            return null;
        }
        $mappings = [];
        $errors = [];
        foreach ($entries as $index => $entry) {
            try {
                $mappings[] = ClaimMapping::forApi(
                    ClaimName::fromString((string) $entry->string('name'), onAnApi: true),
                    ClaimSource::fromString((string) $entry->string('source'), $entry->encoded('value')),
                );
            } catch (InvalidValue $refusal) {
                $errors[] = ['pointer' => '/claims/' . $index, 'detail' => $refusal->getMessage()];
            }
        }
        try {
            return $errors === []
                ? ClaimMappings::of($mappings)
                : new Problem(StatusCodeInterface::STATUS_UNPROCESSABLE_ENTITY, ContractViolation::DETAIL, $errors);
        } catch (InvalidValue $refusal) {
            return new Problem(
                StatusCodeInterface::STATUS_UNPROCESSABLE_ENTITY,
                ContractViolation::DETAIL,
                [['pointer' => '/claims', 'detail' => $refusal->getMessage()]],
            );
        }
    }
}
