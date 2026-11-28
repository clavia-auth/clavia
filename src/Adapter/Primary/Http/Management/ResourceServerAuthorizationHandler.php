<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Management;

use Clavia\Application\Management\ResourceServers\AuthorizationRefused;
use Clavia\Application\Management\ResourceServers\ConfigureAuthorization;
use Clavia\Application\Management\ResourceServers\DisableAuthorization;
use Clavia\Application\Management\ResourceServers\ReadResourceServers;
use Clavia\Application\Port\DecisionEngineFailed;
use Clavia\Domain\Authorization\AuthorizationModel;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\ResourceServer\ResourceServerId;
use Clavia\Domain\Shared\InvalidValue;
use Fig\Http\Message\RequestMethodInterface;
use Fig\Http\Message\StatusCodeInterface;
use LogicException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `/api/v1/resource-servers/{resource_server_id}/authorization`: `GET` (`getResourceServerAuthorization`),
 * `PUT` (`putResourceServerAuthorization`), `DELETE` (`deleteResourceServerAuthorization`).
 *
 * A model or a client the domain refuses is a `422` pointing at it (`/model`, `/clients/1`), and the
 * decision engine's refusal of a model the same, with its code alone. An engine that gives no answer
 * is a `503`: nothing was changed.
 */
final readonly class ResourceServerAuthorizationHandler implements RequestHandlerInterface
{
    public function __construct(
        private ReadResourceServers $read,
        private ConfigureAuthorization $configure,
        private DisableAuthorization $disable,
        private ManagementResponder $responder,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $management = ManagementRequest::of($request);
        $id = ResourceServerId::fromString($management->path('resource_server_id'));

        try {
            switch ($request->getMethod()) {
                case RequestMethodInterface::METHOD_GET:
                    return $this->responder->json(ManagementViews::authorization($this->read->withAuthorization($id)));
                case RequestMethodInterface::METHOD_PUT:
                    return $this->configure($id, $management->body);
                case RequestMethodInterface::METHOD_DELETE:
                    ($this->disable)($id, $management->query('confirm') === 'delete');

                    return $this->responder->noContent();
                default:
                    throw new LogicException('Routed with a method the handler does not serve.');
            }
        } catch (DecisionEngineFailed) {
            return $this->responder->problem(new Problem(
                StatusCodeInterface::STATUS_SERVICE_UNAVAILABLE,
                'The decision engine is unavailable; nothing was changed.',
            ));
        }
    }

    private function configure(ResourceServerId $id, JsonObject $body): ResponseInterface
    {
        try {
            $model = AuthorizationModel::fromJson((string) $body->json('model'));
        } catch (InvalidValue $refusal) {
            return $this->unprocessable('/model', $refusal->getMessage());
        }
        $clients = [];
        foreach ($body->strings('clients') ?? [] as $index => $client) {
            try {
                $clients[] = ClientId::fromString($client);
            } catch (InvalidValue $refusal) {
                return $this->unprocessable('/clients/' . $index, $refusal->getMessage());
            }
        }

        try {
            $api = ($this->configure)($id, $model, $clients, $body->bool('denial_reasons') ?? false);
        } catch (AuthorizationRefused $refusal) {
            return $this->unprocessable($refusal->pointer, $refusal->getMessage());
        } catch (InvalidValue $refusal) {
            return $this->unprocessable('/clients', $refusal->getMessage());
        }

        return $this->responder->json(ManagementViews::authorization($api));
    }

    private function unprocessable(string $pointer, string $detail): ResponseInterface
    {
        return $this->responder->problem(new Problem(
            StatusCodeInterface::STATUS_UNPROCESSABLE_ENTITY,
            ContractViolation::REFUSED,
            [['pointer' => $pointer, 'detail' => $detail]],
        ));
    }
}
