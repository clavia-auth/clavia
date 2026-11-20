<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Ui\Http\OAuth2;

use Clavia\Application\Authentication\DevelopmentAutoLogin;
use Clavia\Application\OAuth2\Authorize\AuthorizationRequest;
use Clavia\Application\OAuth2\Authorize\Authorize;
use Clavia\Application\OAuth2\Authorize\CodeIssued;
use Clavia\Application\OAuth2\Authorize\LoginRequired;
use Clavia\Application\OAuth2\Authorize\RequestRefused;
use Clavia\Domain\OAuth2\OAuth2Error;
use Clavia\Ui\Http\Shared\RequestParameterReader;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `GET|POST /oauth2/authorize` — the authorization endpoint (RFC 6749 §3.1).
 *
 * Translates the request for {@see Authorize} and its decision back into HTTP: a
 * redirect to the client with a code or an error, a redirect to the login page, or — when
 * the client or its redirect URI cannot be trusted — an error answered here, with no
 * redirect at all.
 */
final readonly class AuthorizeHandler implements RequestHandlerInterface
{
    public function __construct(
        private Authorize $authorize,
        private DevelopmentAutoLogin $autoLogin,
        private OAuth2Responder $responder,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $uri = $request->getUri();

        try {
            $outcome = ($this->authorize)(new AuthorizationRequest(
                // RFC 6749 §3.1: the endpoint must support GET and may support POST.
                RequestParameterReader::queryAndForm($request),
                $uri->getPath() . ($uri->getQuery() === '' ? '' : '?' . $uri->getQuery()),
                $this->autoLogin->endUser(),
            ));
        } catch (OAuth2Error $error) {
            return $this->responder->authorizationError($error);
        }

        if ($outcome instanceof CodeIssued) {
            return $this->responder->redirectToClient(
                $outcome->redirectUri,
                ['code' => $outcome->code, 'state' => $outcome->state],
            );
        }

        if ($outcome instanceof RequestRefused) {
            return $this->responder->redirectToClient($outcome->redirectUri, [
                'error' => $outcome->error->error->value,
                'error_description' => $outcome->error->description,
                'state' => $outcome->state,
            ]);
        }

        assert($outcome instanceof LoginRequired);

        // Only the opaque handle travels: the authorization request itself — client_id,
        // redirect_uri, code_challenge — never reaches the login page's URL.
        return $this->responder->redirectWithinServer(
            '/auth/login?' . http_build_query(['state' => $outcome->loginState]),
        );
    }
}
