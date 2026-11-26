<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Management;

use Clavia\Application\Management\Connections\DeleteConnection;
use Clavia\Application\Management\Connections\ReadConnections;
use Clavia\Application\Management\Connections\UpdateConnection;
use Fig\Http\Message\RequestMethodInterface;
use LogicException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `/api/v1/connections/{name}`: `GET` (`getConnection`), `PATCH` (`updateConnection`),
 * `DELETE` (`deleteConnection`).
 */
final readonly class ConnectionHandler implements RequestHandlerInterface
{
    private const array OIDC_FIELDS = [
        'oidc_issuer' => 'issuer',
        'oidc_client_id' => 'client_id',
        'oidc_client_secret' => 'client_secret',
        'oidc_scope' => 'scope',
    ];

    public function __construct(
        private ReadConnections $read,
        private UpdateConnection $update,
        private DeleteConnection $delete,
        private ManagementResponder $responder,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $management = ManagementRequest::of($request);
        $name = $management->path('name');

        switch ($request->getMethod()) {
            case RequestMethodInterface::METHOD_GET:
                return $this->responder->json(ManagementViews::connection($this->read->one($name)));
            case RequestMethodInterface::METHOD_PATCH:
                $body = $management->body;
                $oidc = [];
                foreach (self::OIDC_FIELDS as $field => $setting) {
                    $value = $body->string($field);
                    if ($value !== null) {
                        $oidc[$setting] = $value;
                    }
                }
                /** @var array{issuer?: string, client_id?: string, client_secret?: string, scope?: string} $oidc */
                $connection = ($this->update)(
                    $name,
                    $body->string('display_name'),
                    $body->bool('is_enabled'),
                    $body->bool('is_domain_connection'),
                    $oidc,
                    $body->bool('allow_sign_up'),
                    $body->bool('require_verified_email'),
                    $body->bool('require_provisioning'),
                );

                return $this->responder->json(ManagementViews::connection($this->read->describe($connection)));
            case RequestMethodInterface::METHOD_DELETE:
                ($this->delete)($name);

                return $this->responder->noContent();
            default:
                throw new LogicException('Routed with a method the handler does not serve.');
        }
    }
}
