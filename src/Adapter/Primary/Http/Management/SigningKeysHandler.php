<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Management;

use Clavia\Application\Management\Conflict;
use Clavia\Application\Oidc\Keys\ListSigningKeys;
use Clavia\Application\Oidc\Keys\RotateSigningKey;
use Clavia\Application\Port\EncryptionUnavailable;
use Fig\Http\Message\StatusCodeInterface;
use LogicException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `GET /api/v1/signing-keys` (`listSigningKeys`) and `POST /api/v1/signing-keys/rotate`
 * (`rotateSigningKey`): what `clavia keys:list` and `keys:rotate` do, for the `postgres`
 * backend, whose keys this server keeps.
 *
 * A key is described by its `kid`, algorithm and place in the rotation, never by its material:
 * the private key never leaves the signing backend, and the public one is the JWKS's to publish.
 * Any other backend keeps its keys at the provider, where they are rotated; both operations
 * answer `409` there, and the use cases are not even built (they would need a key store this
 * server does not have).
 */
final readonly class SigningKeysHandler implements RequestHandlerInterface
{
    /**
     * @param ListSigningKeys|null  $list   Null when the keys are the provider's.
     * @param RotateSigningKey|null $rotate Null when the keys are the provider's.
     */
    public function __construct(
        private ?ListSigningKeys $list,
        private ?RotateSigningKey $rotate,
        private ManagementResponder $responder,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        if ($this->list === null || $this->rotate === null) {
            throw new Conflict('This deployment keeps its signing keys at the provider: rotate them there.');
        }

        if ($request->getMethod() === 'GET') {
            return $this->responder->jsonList(array_map(ManagementViews::signingKey(...), ($this->list)()));
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

        return $this->responder->json(ManagementViews::rotation($rotation));
    }
}
