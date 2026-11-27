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
use Clavia\Adapter\Primary\Http\Shared\Message;
use Clavia\Adapter\Primary\Http\Shared\RequestCookies;
use Clavia\Adapter\Primary\Http\Shared\RequestParameterReader;
use Clavia\Application\Authentication\SignIn\EmailVerificationRequired;
use Clavia\Application\Authentication\SignIn\PasswordSignIn;
use Clavia\Application\Authentication\SignIn\PasswordSignInUnavailable;
use Clavia\Application\Authentication\SignIn\SecondFactorRequired;
use Clavia\Application\Authentication\SignIn\SignedIn;
use Clavia\Application\Authentication\SignIn\SignInRequestExpired;
use Clavia\Application\Authentication\SignIn\SignInWithPassword;
use Fig\Http\Message\StatusCodeInterface;
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
 * challenge cookie instead of a session ({@see MfaChallengeHandler}). When its pool requires
 * a verified address it has not proved, it leads to "check your email" instead: a new
 * verification link was sent.
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
        private LoginForm $loginForm,
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
            return $this->refuse(
                $request,
                $loginState,
                $email,
                Message::of(LoginPages::EXPIRED_FORM),
                StatusCodeInterface::STATUS_BAD_REQUEST,
            );
        }

        $outcome = ($this->signIn)(new PasswordSignIn(
            $email,
            $form->get('password') ?? '',
            ClientAddress::of($request),
            $loginState,
            RequestCookies::first($request, $this->cookies->sessionCookieName),
            $this->responder->language($request),
        ));

        if ($outcome instanceof SignInRequestExpired) {
            return $this->responder->page($request, LoginPages::expired());
        }
        if ($outcome instanceof SecondFactorRequired) {
            // No session yet: the second step is a page of its own, holding the
            // challenge in a cookie scoped to /auth.
            return $this->responder->redirect(
                MfaPages::CHALLENGE_PATH,
                [$this->cookies->mfaChallenge($outcome->challenge)],
            );
        }
        if ($outcome instanceof EmailVerificationRequired) {
            // The right password, but the address is not proved yet: a new link went out.
            return $this->responder->page(
                $request,
                AccountPages::checkInbox($outcome->email, 'unverified', $loginState),
            );
        }
        if ($outcome instanceof PasswordSignInUnavailable) {
            return $this->refuse(
                $request,
                $loginState,
                $email,
                Message::of(LoginPages::PASSWORD_UNAVAILABLE),
                StatusCodeInterface::STATUS_BAD_REQUEST,
            );
        }
        if (! $outcome instanceof SignedIn) {
            return $this->refuse(
                $request,
                $loginState,
                $email,
                Message::of(LoginPages::INVALID_CREDENTIALS),
                StatusCodeInterface::STATUS_UNAUTHORIZED,
            );
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
        Message $error,
        int $status,
    ): ResponseInterface {
        return $this->loginForm->render($request, $loginState, $email, $error, $status);
    }
}
