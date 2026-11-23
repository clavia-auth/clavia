<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Auth;

use Clavia\Adapter\Primary\Http\Shared\ClientAddress;
use Clavia\Adapter\Primary\Http\Shared\RequestParameterReader;
use Clavia\Application\Authentication\LoginPage\DescribeLoginPage;
use Clavia\Application\Authentication\Passwordless\PasswordlessCodeSent;
use Clavia\Application\Authentication\Passwordless\PasswordlessLinkSent;
use Clavia\Application\Authentication\Passwordless\PasswordlessStart;
use Clavia\Application\Authentication\Passwordless\StartPasswordlessSignIn;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `POST /auth/passwordless/start` — the login page's email form: send a code or a link.
 *
 * A code leads to `/auth/passwordless/code`, with the challenge's handle in a cookie: a
 * redirect rather than the page itself, so reloading it does not send another email. A
 * link leads nowhere in this browser — it works from whichever opens it — so the answer
 * is the "check your email" page. Anything refused re-renders the login form with the
 * same `state`: `400` for a bad request or an application that does not sign people in
 * by email, `429` past the send limit, `503` when mail cannot go out.
 */
final readonly class PasswordlessStartHandler implements RequestHandlerInterface
{
    public function __construct(
        private StartPasswordlessSignIn $start,
        private DescribeLoginPage $describe,
        private AuthPageResponder $responder,
        private AuthCookies $cookies,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $form = RequestParameterReader::form($request);
        $email = trim($form->get('email') ?? '');
        $loginState = $form->get('state');

        if (! CsrfToken::isValid($request, $form->get('csrf_token'))) {
            return $this->refuse($request, $loginState, $email, LoginPages::EXPIRED_FORM, 400);
        }

        $outcome = ($this->start)(new PasswordlessStart(
            $email,
            $form->get('mode') ?? '',
            ClientAddress::of($request),
            $loginState,
        ));

        if ($outcome instanceof PasswordlessCodeSent) {
            return $this->responder->redirect(
                PasswordlessPages::CODE_PATH,
                [$this->cookies->passwordless($outcome->handle)],
            );
        }
        if ($outcome instanceof PasswordlessLinkSent) {
            return $this->responder->page($request, PasswordlessPages::linkSent($outcome->email));
        }

        return $this->refuse(
            $request,
            $loginState,
            $email,
            PasswordlessPages::message($outcome->reason),
            PasswordlessPages::status($outcome->reason),
        );
    }

    private function refuse(
        ServerRequestInterface $request,
        ?string $loginState,
        string $email,
        string $error,
        int $status,
    ): ResponseInterface {
        return $this->responder->page(
            $request,
            LoginPages::form(
                $loginState,
                $this->describe->formOrigins($loginState),
                $this->describe->methods($loginState),
                $email,
                $error,
                $status,
            ),
        );
    }
}
