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
use Clavia\Application\Authentication\SignIn\PasswordSignInUnavailable;
use Clavia\Application\Authentication\SignIn\SecondFactorRequired;
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
 * When the account has a second factor, a correct password leads to `/auth/mfa` with a
 * challenge cookie instead of a session ({@see MfaChallengeHandler}).
 *
 * A failure re-renders the form with the same `state`, so the person is not sent back
 * to the application to start over: `400` when the CSRF check fails or the application
 * lets nobody in with a password, `401` when the credentials do — one message for every
 * reason, see {@see LoginPages}.
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
            ClientAddress::of($request),
            $loginState,
            RequestCookies::first($request, $this->cookies->sessionCookieName),
        ));

        if ($outcome instanceof SecondFactorRequired) {
            // No session yet: the second step is a page of its own, holding the
            // challenge in a cookie scoped to /auth.
            return $this->responder->redirect(
                MfaPages::CHALLENGE_PATH,
                [$this->cookies->mfaChallenge($outcome->challenge)],
            );
        }
        if ($outcome instanceof PasswordSignInUnavailable) {
            return $this->refuse($request, $loginState, $email, LoginPages::PASSWORD_UNAVAILABLE, 400);
        }
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
            LoginPages::form($loginState, $origins, $this->describe->methods($loginState), $email, $error, $status),
        );
    }
}
