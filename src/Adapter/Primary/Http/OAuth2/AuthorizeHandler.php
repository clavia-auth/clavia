<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\OAuth2;

use Clavia\Adapter\Primary\Http\Auth\AuthCookies;
use Clavia\Adapter\Primary\Http\Auth\ConsentPages;
use Clavia\Adapter\Primary\Http\Shared\RequestCookies;
use Clavia\Adapter\Primary\Http\Shared\RequestParameterReader;
use Clavia\Application\Authentication\ResolveEndUser;
use Clavia\Application\OAuth2\Authorize\AuthorizationRequest;
use Clavia\Application\OAuth2\Authorize\Authorize;
use Clavia\Application\OAuth2\Authorize\CodeIssued;
use Clavia\Application\OAuth2\Authorize\ConsentRequired;
use Clavia\Application\OAuth2\Authorize\LoginRequired;
use Clavia\Application\OAuth2\Authorize\RequestRefused;
use Clavia\Domain\OAuth2\OAuth2Error;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `GET|POST /oauth2/authorize` — the authorization endpoint (RFC 6749 §3.1).
 *
 * Translates the request for {@see Authorize} and its decision back into HTTP: a
 * redirect to the client with a code or an error, a redirect to the login page or the
 * consent screen, or — when the client or its redirect URI cannot be trusted — an error
 * answered here, with no redirect at all.
 */
final readonly class AuthorizeHandler implements RequestHandlerInterface
{
    public function __construct(
        private Authorize $authorize,
        private ResolveEndUser $resolveEndUser,
        private OAuth2Responder $responder,
        private AuthCookies $cookies,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        try {
            $outcome = ($this->authorize)(new AuthorizationRequest(
                // RFC 6749 §3.1: the endpoint must support GET and may support POST.
                RequestParameterReader::queryAndForm($request),
                $request->getUri()->getPath(),
                ($this->resolveEndUser)(RequestCookies::first($request, $this->cookies->sessionCookieName)),
            ));
        } catch (OAuth2Error $error) {
            return $this->responder->authorizationError($request, $error);
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

        // Only the opaque handle travels: the authorization request itself — client_id,
        // redirect_uri, code_challenge — never reaches the login page's or the consent
        // screen's URL.
        if ($outcome instanceof ConsentRequired) {
            return $this->responder->redirectWithinServer(
                ConsentPages::PATH . '?' . http_build_query(['state' => $outcome->consentState]),
            );
        }

        assert($outcome instanceof LoginRequired);

        return $this->responder->redirectWithinServer(
            '/auth/login?' . http_build_query(['state' => $outcome->loginState]),
        );
    }
}
