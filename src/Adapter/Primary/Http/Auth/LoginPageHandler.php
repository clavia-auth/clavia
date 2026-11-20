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
use Clavia\Application\Authentication\LoginPage\DescribeLoginPage;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `GET /auth/login` — the sign-in form.
 *
 * `state` is the opaque handle `/oauth2/authorize` parked the authorization request
 * behind; the form carries it back. A visitor already signed in, with no `state`, is
 * told who they are instead of being asked to sign in again for nothing.
 */
final readonly class LoginPageHandler implements RequestHandlerInterface
{
    public function __construct(
        private DescribeLoginPage $describe,
        private AuthPageResponder $responder,
        private AuthCookies $cookies,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $loginState = RequestParameterReader::query($request)->get('state');
        $page = ($this->describe)($loginState, RequestCookies::first($request, $this->cookies->sessionCookieName));

        return $this->responder->page(
            $request,
            $page->signedInAs !== null
                ? LoginPages::signedIn($page->signedInAs)
                : LoginPages::form($loginState, $page->formOrigins),
        );
    }
}
