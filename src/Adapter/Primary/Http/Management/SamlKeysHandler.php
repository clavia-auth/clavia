<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Management;

use Clavia\Application\Connection\Saml\ListServiceProviderKeys;
use Clavia\Application\Connection\Saml\RotateServiceProviderKeys;
use Clavia\Application\Port\EncryptionUnavailable;
use Fig\Http\Message\StatusCodeInterface;
use LogicException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `GET /api/v1/saml-keys` and `POST /api/v1/saml-keys/rotate`: the SAML service provider's keys by
 * their certificates and their place in the rotation, as `/api/v1/signing-keys` does for token keys;
 * never key material (docs/design/saml-connections.md §6).
 */
final readonly class SamlKeysHandler implements RequestHandlerInterface
{
    public function __construct(
        private ListServiceProviderKeys $list,
        private RotateServiceProviderKeys $rotate,
        private ManagementResponder $responder,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        if ($request->getMethod() === 'GET') {
            return $this->responder->jsonList(
                array_map(ManagementViews::samlKey(...), ($this->list)()->keys),
            );
        }
        if ($request->getMethod() !== 'POST') {
            throw new LogicException('Routed with a method the handler does not serve.');
        }

        try {
            $rotation = ($this->rotate)();
        } catch (EncryptionUnavailable $unavailable) {
            return $this->responder->problem(
                new Problem(StatusCodeInterface::STATUS_SERVICE_UNAVAILABLE, $unavailable->getMessage()),
            );
        }

        return $this->responder->json(ManagementViews::samlKeyRotation($rotation));
    }
}
