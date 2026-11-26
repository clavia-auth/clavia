<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Auth;

use Clavia\Adapter\Primary\Http\Shared\Message;
use Clavia\Application\Authentication\LoginPage\DescribeLoginPage;
use Clavia\Application\Authentication\SignIn\BeginPasskeySignIn;
use Fig\Http\Message\StatusCodeInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * The sign-in form as a response: the ways in the application allows, and — when a passkey is
 * one — a fresh ceremony for it, behind the `clavia_webauthn` cookie. A ceremony answers once, so
 * every rendering opens its own: the page, and the page again after a refusal.
 */
final readonly class LoginForm
{
    public function __construct(
        private DescribeLoginPage $describe,
        private BeginPasskeySignIn $beginPasskey,
        private AuthPageResponder $responder,
        private AuthCookies $cookies,
    ) {
    }

    public function render(
        ServerRequestInterface $request,
        #[\SensitiveParameter] ?string $loginState,
        ?string $email = null,
        ?Message $error = null,
        int $status = StatusCodeInterface::STATUS_OK,
    ): ResponseInterface {
        $methods = $this->describe->methods($loginState);
        $passkey = $methods->passkey ? ($this->beginPasskey)($loginState) : null;

        return $this->responder->page(
            $request,
            LoginPages::form(
                $loginState,
                $this->describe->formOrigins($loginState),
                $methods,
                $email,
                $error,
                $status,
                $passkey,
            ),
            $passkey === null ? [] : [$this->cookies->webauthn($passkey->handle)],
        );
    }
}
