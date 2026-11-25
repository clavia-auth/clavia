<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Management;

use Clavia\Application\Management\Connections\ReadConnections;
use Clavia\Application\Management\Connections\RefreshSamlMetadata;
use Clavia\Application\Management\Connections\SamlMetadataRefused;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/** `POST /api/v1/connections/{name}/refresh-metadata`: a SAML connection's metadata read again from its URL. */
final readonly class ConnectionMetadataRefreshHandler implements RequestHandlerInterface
{
    public function __construct(
        private RefreshSamlMetadata $refresh,
        private ReadConnections $read,
        private ManagementResponder $responder,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        try {
            $connection = ($this->refresh)(ManagementRequest::of($request)->path('name'));
        } catch (SamlMetadataRefused $refused) {
            return $this->responder->problem(ConnectionsHandler::metadataProblem($refused));
        }

        return $this->responder->json(ManagementViews::connection($this->read->describe($connection)));
    }
}
