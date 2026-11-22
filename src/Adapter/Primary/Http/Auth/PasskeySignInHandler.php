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
use Clavia\Application\Authentication\SignIn\PasskeySignIn;
use Clavia\Application\Authentication\SignIn\SecondFactorRequired;
use Clavia\Application\Authentication\SignIn\SignedIn;
use Clavia\Application\Authentication\SignIn\SignInWithPasskey;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `POST /auth/passkey` — signing in with a passkey, from the login page (docs/design/passkeys.md
 * §6.2).
 *
 * `passkeys.js` posts the browser's answer here, from the autofill or the button, with the page's
 * `state` and CSRF token. A sign-in goes on as a password sign-in does: to the authorization
 * request it answers, or to `/auth/mfa` when a second factor follows. A refusal is the login page
 * again, with the same message as a wrong password, whatever it was (`401`), and a fresh ceremony.
 */
final readonly class PasskeySignInHandler implements RequestHandlerInterface
{
    public function __construct(
        private SignInWithPasskey $signIn,
        private LoginForm $loginForm,
        private AuthPageResponder $responder,
        private AuthCookies $cookies,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $form = RequestParameterReader::form($request);
        $loginState = $form->get('state');
        if (! CsrfToken::isValid($request, $form->get('csrf_token'))) {
            return $this->loginForm->render($request, $loginState, null, LoginPages::EXPIRED_FORM, 400);
        }

        $outcome = ($this->signIn)(new PasskeySignIn(
            $loginState,
            RequestCookies::first($request, AuthCookies::WEBAUTHN) ?? '',
            $form->get('credential') ?? '',
            ClientAddress::of($request),
            RequestCookies::first($request, $this->cookies->sessionCookieName),
        ));

        if ($outcome instanceof SecondFactorRequired) {
            return $this->responder->redirect(MfaPages::CHALLENGE_PATH, [
                $this->cookies->mfaChallenge($outcome->challenge),
                $this->cookies->expireWebAuthn(),
            ]);
        }
        if ($outcome instanceof SignedIn) {
            return $this->responder->redirect($outcome->nextUrl, [
                $this->cookies->session($outcome->sessionId),
                $this->cookies->expireWebAuthn(),
                $this->cookies->expireCsrf(),
            ]);
        }

        return $this->loginForm->render($request, $loginState, null, LoginPages::INVALID_CREDENTIALS, 401);
    }
}
