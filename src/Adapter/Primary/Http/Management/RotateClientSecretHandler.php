<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Management;

use Clavia\Application\Management\Clients\RotateClientSecret;
use Clavia\Domain\Client\ClientId;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `POST /api/v1/clients/{client_id}/rotate-secret` (`rotateClientSecret`): the client
 * with its new secret, the only time that secret is shown.
 */
final readonly class RotateClientSecretHandler implements RequestHandlerInterface
{
    public function __construct(
        private RotateClientSecret $rotate,
        private ManagementResponder $responder,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $id = ClientId::fromString(ManagementRequest::of($request)->path('client_id'));

        return $this->responder->json(ManagementViews::clientWithSecret(($this->rotate)($id)));
    }
}
