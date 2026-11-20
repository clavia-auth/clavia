<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Auth;

use Clavia\Adapter\Primary\Http\Shared\RequestCookies;
use Clavia\Adapter\Primary\Http\Shared\RequestParameterReader;
use Clavia\Application\Authentication\SignOut;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `POST /auth/logout` — end the session and clear its cookie.
 *
 * POST only: a logout a bare GET could trigger is forgeable from any page on the web
 * (an `<img src>` is enough), and this one deletes a session server-side. It carries no
 * CSRF token because the session cookie is `SameSite=Lax`: a cross-site POST arrives
 * without it and ends nothing.
 *
 * `next` may leave this server, to an origin some client registered; see {@see SignOut}.
 */
final readonly class LogoutHandler implements RequestHandlerInterface
{
    public function __construct(
        private SignOut $signOut,
        private AuthPageResponder $responder,
        private AuthCookies $cookies,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $target = ($this->signOut)(
            RequestCookies::first($request, $this->cookies->sessionCookieName),
            RequestParameterReader::query($request)->get('next'),
        );

        return $this->responder->redirect($target, [$this->cookies->expireSession()]);
    }
}
