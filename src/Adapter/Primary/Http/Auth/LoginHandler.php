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
use Clavia\Application\Authentication\SignIn\PasswordSignIn;
use Clavia\Application\Authentication\SignIn\SignedIn;
use Clavia\Application\Authentication\SignIn\SignInWithPassword;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `POST /auth/login` — check the credentials and start a session.
 *
 * The body is read only as `application/x-www-form-urlencoded`, which is all the form
 * sends: a multipart body is not recognised, so file-upload handling never reaches the
 * most sensitive endpoint of the product.
 *
 * A failure re-renders the form with the same `state`, so the person is not sent back
 * to the application to start over: `400` when the CSRF check fails, `401` when the
 * credentials do — one message for every reason, see {@see LoginPages}.
 */
final readonly class LoginHandler implements RequestHandlerInterface
{
    public function __construct(
        private SignInWithPassword $signIn,
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

        $outcome = ($this->signIn)(new PasswordSignIn(
            $email,
            $form->get('password') ?? '',
            self::clientAddress($request),
            $loginState,
            RequestCookies::first($request, $this->cookies->sessionCookieName),
        ));

        if (! $outcome instanceof SignedIn) {
            return $this->refuse($request, $loginState, $email, LoginPages::INVALID_CREDENTIALS, 401);
        }

        // The CSRF cookie has done its job; the next form gets a fresh one.
        return $this->responder->redirect(
            $outcome->nextUrl,
            [$this->cookies->session($outcome->sessionId), $this->cookies->expireCsrf()],
        );
    }

    private function refuse(
        ServerRequestInterface $request,
        ?string $loginState,
        string $email,
        string $error,
        int $status,
    ): ResponseInterface {
        $origins = $this->describe->formOrigins($loginState);

        return $this->responder->page(
            $request,
            LoginPages::form($loginState, $origins, $email, $error, $status),
        );
    }

    /**
     * The address the web server reports. Behind Caddy over FastCGI that is the
     * client's own; no forwarded header is consulted.
     */
    private static function clientAddress(ServerRequestInterface $request): string
    {
        /** @var mixed $address */
        $address = $request->getServerParams()['REMOTE_ADDR'] ?? null;

        return is_string($address) && $address !== '' ? $address : 'unknown';
    }
}
