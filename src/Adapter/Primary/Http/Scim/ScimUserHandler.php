<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Scim;

use Clavia\Application\Provisioning\Users\ReadScimUsers;
use LogicException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `GET /scim/v2/Users/{id}` (RFC 7644 §3.4.1): an account of the caller's connection. Any other id,
 * another connection's account included, is `404` (docs/design/scim-provisioning.md §7).
 */
final readonly class ScimUserHandler implements RequestHandlerInterface
{
    /** @param non-empty-string $baseUrl */
    public function __construct(
        private ReadScimUsers $read,
        private ScimResponder $responder,
        private string $baseUrl,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        /** @var mixed $id */
        $id = $request->getAttribute('id');
        if (! is_string($id)) {
            throw new LogicException('Routed without an id.');
        }
        $user = $this->read->find(ScimRequest::caller($request), $id);

        return $user === null
            ? $this->responder->notFound()
            : $this->responder->json(ScimUserDocument::of($user, $this->baseUrl));
    }
}
