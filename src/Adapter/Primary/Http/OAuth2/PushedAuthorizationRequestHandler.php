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
use Clavia\Application\OAuth2\Par\PushAuthorizationRequest;
use Clavia\Application\OAuth2\Token\TokenRequest;
use Clavia\Domain\OAuth2\OAuth2Error;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerInterface;

/**
 * `POST /oauth2/par` — the pushed authorization request endpoint (RFC 9126 §2).
 *
 * The request is the form body, as at the token endpoint, and the answer is `201` with the
 * `request_uri` and its `expires_in` (§2.2), or the token endpoint's error document (§2.3).
 */
final readonly class PushedAuthorizationRequestHandler implements RequestHandlerInterface
{
    public function __construct(
        private PushAuthorizationRequest $push,
        private OAuth2Responder $responder,
        private LoggerInterface $logger,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $authorization = $request->getHeaderLine('Authorization');

        try {
            $accepted = ($this->push)(new TokenRequest(
                RequestParameterReader::form($request),
                $authorization === '' ? null : $authorization,
                ClientAddress::of($request),
                array_values($request->getHeader('DPoP')),
            ));
        } catch (OAuth2Error $error) {
            if ($error->reason !== null) {
                $this->logger->info('A DPoP proof was refused at the PAR endpoint: {reason}', [
                    'reason' => $error->reason,
                ]);
            }

            return $this->responder->tokenError($error);
        } catch (TooManyFailedRequests $refusal) {
            return $this->responder->tooManyFailures($refusal);
        }

        $response = $this->responder->created([
            'request_uri' => $accepted->requestUri,
            'expires_in' => $accepted->expiresIn,
        ]);

        return $accepted->dpopNonce === null ? $response : $response->withHeader('DPoP-Nonce', $accepted->dpopNonce);
    }
}
