<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\OAuth2;

use Clavia\Adapter\Primary\Http\Shared\ClientAddress;
use Clavia\Adapter\Primary\Http\Shared\RequestParameterReader;
use Clavia\Application\OAuth2\ClientAuthentication\TooManyFailedRequests;
use Clavia\Application\OAuth2\Token\TokenRequest;
use Clavia\Application\OAuth2\TokenManagement\RevokeToken;
use Clavia\Domain\OAuth2\OAuth2Error;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `POST /oauth2/revoke` — RFC 7009 §2. A revoked token, and an unknown one, is a `200`
 * with an empty body (§2.2: the client ignores the body).
 */
final readonly class RevocationHandler implements RequestHandlerInterface
{
    public function __construct(
        private RevokeToken $revoke,
        private OAuth2Responder $responder,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $authorization = $request->getHeaderLine('Authorization');

        try {
            ($this->revoke)(new TokenRequest(
                RequestParameterReader::form($request),
                $authorization === '' ? null : $authorization,
                ClientAddress::of($request),
            ));
        } catch (OAuth2Error $error) {
            return $this->responder->tokenError($error);
        } catch (TooManyFailedRequests $refusal) {
            return $this->responder->tooManyFailures($refusal);
        }

        return $this->responder->done();
    }
}
