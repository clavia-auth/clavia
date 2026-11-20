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
use Clavia\Application\Authentication\Mfa\CompleteSecondFactor;
use Clavia\Application\Authentication\Mfa\DescribeSecondFactorPage;
use Clavia\Application\Authentication\Mfa\SecondFactorAttempt;
use Clavia\Application\Authentication\Mfa\SecondFactorRejected;
use Clavia\Application\Authentication\SignIn\SignedIn;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `GET|POST /auth/mfa` — the second step of a sign-in.
 *
 * Reached only with a challenge cookie, set when a correct password met an account with a
 * second factor. Without a live challenge there is nothing to answer, and the browser goes
 * back to the login page. A wrong code re-renders the form (401) while the challenge has
 * attempts left; the last one sends the browser back to its password.
 */
final readonly class MfaChallengeHandler implements RequestHandlerInterface
{
    public function __construct(
        private DescribeSecondFactorPage $describe,
        private CompleteSecondFactor $complete,
        private AuthPageResponder $responder,
        private AuthCookies $cookies,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $challenge = RequestCookies::first($request, AuthCookies::MFA_CHALLENGE);
        $formOrigins = ($this->describe)($challenge);
        if ($challenge === null || $formOrigins === null) {
            return $this->backToLogin();
        }

        if ($request->getMethod() !== 'POST') {
            return $this->responder->page($request, MfaPages::challenge($formOrigins));
        }

        $form = RequestParameterReader::form($request);
        if (! CsrfToken::isValid($request, $form->get('csrf_token'))) {
            return $this->responder->page(
                $request,
                MfaPages::challenge($formOrigins, LoginPages::EXPIRED_FORM, 400),
            );
        }

        $outcome = ($this->complete)(new SecondFactorAttempt(
            $challenge,
            $form->get('code') ?? '',
            ClientAddress::of($request),
            RequestCookies::first($request, $this->cookies->sessionCookieName),
        ));

        if ($outcome instanceof SignedIn) {
            return $this->responder->redirect($outcome->nextUrl, [
                $this->cookies->session($outcome->sessionId),
                $this->cookies->expireMfaChallenge(),
                $this->cookies->expireCsrf(),
            ]);
        }
        if ($outcome instanceof SecondFactorRejected) {
            return $this->responder->page(
                $request,
                MfaPages::challenge($formOrigins, MfaPages::INVALID_CODE, 401),
            );
        }

        return $this->backToLogin();
    }

    private function backToLogin(): ResponseInterface
    {
        return $this->responder->redirect('/auth/login', [$this->cookies->expireMfaChallenge()]);
    }
}
