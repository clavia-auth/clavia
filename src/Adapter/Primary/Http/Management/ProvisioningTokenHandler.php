<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Management;

use Clavia\Application\Management\ProvisioningTokens\ReadProvisioningTokens;
use Clavia\Application\Management\ProvisioningTokens\RevokeProvisioningToken;
use Clavia\Domain\Provisioning\ProvisioningTokenId;
use LogicException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `/api/v1/provisioning-tokens/{provisioning_token_id}`: `GET` describes it (`getProvisioningToken`),
 * `DELETE` revokes it (`revokeProvisioningToken`).
 */
final readonly class ProvisioningTokenHandler implements RequestHandlerInterface
{
    public function __construct(
        private ReadProvisioningTokens $read,
        private RevokeProvisioningToken $revoke,
        private ManagementResponder $responder,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $id = ProvisioningTokenId::fromString(ManagementRequest::of($request)->path('provisioning_token_id'));

        return match ($request->getMethod()) {
            'GET' => $this->responder->json(
                ManagementViews::provisioningToken($this->read->find($id), $this->read->now()),
            ),
            'DELETE' => $this->revoked($id),
            default => throw new LogicException('Routed with a method the handler does not serve.'),
        };
    }

    private function revoked(ProvisioningTokenId $id): ResponseInterface
    {
        ($this->revoke)($id);

        return $this->responder->noContent();
    }
}
