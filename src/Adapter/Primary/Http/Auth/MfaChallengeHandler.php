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
use Clavia\Adapter\Primary\Http\Shared\RequestCookies;
use Clavia\Adapter\Primary\Http\Shared\RequestParameterReader;
use Clavia\Application\Authentication\Mfa\BeginPasskeySecondFactor;
use Clavia\Application\Authentication\Mfa\CompletePasskeySecondFactor;
use Clavia\Application\Authentication\Mfa\CompleteSecondFactor;
use Clavia\Application\Authentication\Mfa\DescribeSecondFactorPage;
use Clavia\Application\Authentication\Mfa\PasskeySecondFactorAttempt;
use Clavia\Application\Authentication\Mfa\SecondFactorAttempt;
use Clavia\Application\Authentication\Mfa\SecondFactorOutcome;
use Clavia\Application\Authentication\Mfa\SecondFactorPage;
use Clavia\Application\Authentication\Mfa\SecondFactorRejected;
use Clavia\Application\Authentication\SignIn\SignedIn;
use Fig\Http\Message\StatusCodeInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `GET|POST /auth/mfa` and `POST /auth/mfa/passkey` — the second step of a sign-in.
 *
 * Reached only with a challenge cookie, set when a correct password met an account with a
 * second factor. Without a live challenge there is nothing to answer, and the browser goes
 * back to the login page. The account answers with a code from its authenticator app, a
 * recovery code, or — when it holds one — a passkey: the page then carries the options of a
 * fresh ceremony, behind the `clavia_webauthn` cookie, and `passkeys.js` posts the browser's
 * answer to `/auth/mfa/passkey`. A wrong answer of either kind re-renders the page (401) while
 * the challenge has attempts left; the last one sends the browser back to its password.
 */
final readonly class MfaChallengeHandler implements RequestHandlerInterface
{
    public const string PASSKEY_PATH = '/auth/mfa/passkey';

    public function __construct(
        private DescribeSecondFactorPage $describe,
        private CompleteSecondFactor $complete,
        private BeginPasskeySecondFactor $beginPasskey,
        private CompletePasskeySecondFactor $completePasskey,
        private AuthPageResponder $responder,
        private AuthCookies $cookies,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $challenge = RequestCookies::first($request, AuthCookies::MFA_CHALLENGE);
        $page = ($this->describe)($challenge);
        if ($challenge === null || $page === null) {
            return $this->backToLogin();
        }

        if ($request->getMethod() !== 'POST') {
            return $this->page($request, $challenge, $page);
        }

        $form = RequestParameterReader::form($request);
        if (! CsrfToken::isValid($request, $form->get('csrf_token'))) {
            return $this->page(
                $request,
                $challenge,
                $page,
                LoginPages::EXPIRED_FORM,
                StatusCodeInterface::STATUS_BAD_REQUEST,
            );
        }

        if ($request->getUri()->getPath() === self::PASSKEY_PATH) {
            return $this->answered($request, $challenge, $page, ($this->completePasskey)(new PasskeySecondFactorAttempt(
                $challenge,
                RequestCookies::first($request, AuthCookies::WEBAUTHN) ?? '',
                $form->get('credential') ?? '',
                ClientAddress::of($request),
                RequestCookies::first($request, $this->cookies->sessionCookieName),
            )), MfaPages::INVALID_PASSKEY);
        }

        return $this->answered($request, $challenge, $page, ($this->complete)(new SecondFactorAttempt(
            $challenge,
            $form->get('code') ?? '',
            ClientAddress::of($request),
            RequestCookies::first($request, $this->cookies->sessionCookieName),
        )), MfaPages::INVALID_CODE);
    }

    private function answered(
        ServerRequestInterface $request,
        string $challenge,
        SecondFactorPage $page,
        SecondFactorOutcome $outcome,
        string $rejected,
    ): ResponseInterface {
        if ($outcome instanceof SignedIn) {
            return $this->responder->redirect($outcome->nextUrl, [
                $this->cookies->session($outcome->sessionId),
                $this->cookies->expireMfaChallenge(),
                $this->cookies->expireWebAuthn(),
                $this->cookies->expireCsrf(),
            ]);
        }
        if ($outcome instanceof SecondFactorRejected) {
            return $this->page($request, $challenge, $page, $rejected, StatusCodeInterface::STATUS_UNAUTHORIZED);
        }

        return $this->backToLogin();
    }

    /**
     * The page, with a fresh passkey ceremony when the account can answer with one: a ceremony
     * answers once, so every rendering opens its own.
     */
    private function page(
        ServerRequestInterface $request,
        string $challenge,
        SecondFactorPage $page,
        ?string $error = null,
        int $status = StatusCodeInterface::STATUS_OK,
    ): ResponseInterface {
        $options = $page->passkey ? ($this->beginPasskey)($challenge) : null;

        return $this->responder->page(
            $request,
            MfaPages::challenge($page, $options, $error, $status),
            $options === null ? [] : [$this->cookies->webauthn($options->handle)],
        );
    }

    private function backToLogin(): ResponseInterface
    {
        return $this->responder->redirect('/auth/login', [
            $this->cookies->expireMfaChallenge(),
            $this->cookies->expireWebAuthn(),
        ]);
    }
}
