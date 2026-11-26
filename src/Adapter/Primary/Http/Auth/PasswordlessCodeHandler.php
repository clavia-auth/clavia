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
use Clavia\Adapter\Primary\Http\Shared\RequestCookies;
use Clavia\Adapter\Primary\Http\Shared\RequestParameterReader;
use Clavia\Application\Authentication\Passwordless\AnswerPasswordlessCode;
use Clavia\Application\Authentication\Passwordless\DescribePasswordlessChallenge;
use Clavia\Application\Authentication\Passwordless\PasswordlessCodeRejected;
use Clavia\Application\Authentication\Passwordless\PasswordlessFailure;
use Clavia\Application\Authentication\SignIn\SecondFactorRequired;
use Clavia\Application\Authentication\SignIn\SignedIn;
use Clavia\Domain\Authentication\PasswordlessMode;
use Fig\Http\Message\RequestMethodInterface;
use Fig\Http\Message\StatusCodeInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `GET|POST /auth/passwordless/code` — where the code sent by email is typed.
 *
 * Only for the browser that asked: the challenge is the one its `clavia_passwordless`
 * cookie names. Without one — another browser, an expired code, the last wrong attempt
 * spent — the person is sent back to the login page to ask again. A wrong code with
 * attempts left re-renders the page with `401`.
 *
 * A right one ends like a password: a session, or the second-factor page for an account
 * that has one.
 */
final readonly class PasswordlessCodeHandler implements RequestHandlerInterface
{
    public function __construct(
        private DescribePasswordlessChallenge $describe,
        private AnswerPasswordlessCode $answer,
        private AuthPageResponder $responder,
        private AuthCookies $cookies,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $handle = RequestCookies::first($request, AuthCookies::PASSWORDLESS);

        if ($request->getMethod() !== RequestMethodInterface::METHOD_POST) {
            $prompt = ($this->describe)($handle, PasswordlessMode::Code);

            return $prompt === null
                ? $this->backToLogin()
                : $this->responder->page($request, PasswordlessPages::code($prompt));
        }

        $form = RequestParameterReader::form($request);
        if (! CsrfToken::isValid($request, $form->get('csrf_token'))) {
            $prompt = ($this->describe)($handle, PasswordlessMode::Code);

            return $prompt === null
                ? $this->backToLogin()
                : $this->responder->page(
                    $request,
                    PasswordlessPages::code(
                        $prompt,
                        Message::of(LoginPages::EXPIRED_FORM),
                        StatusCodeInterface::STATUS_BAD_REQUEST,
                    ),
                );
        }

        $outcome = ($this->answer)(
            $handle,
            $form->get('code') ?? '',
            RequestCookies::first($request, $this->cookies->sessionCookieName),
        );

        if ($outcome instanceof SignedIn) {
            return $this->responder->redirect($outcome->nextUrl, [
                $this->cookies->session($outcome->sessionId),
                $this->cookies->expireCsrf(),
                $this->cookies->expirePasswordless(),
            ]);
        }
        if ($outcome instanceof SecondFactorRequired) {
            return $this->responder->redirect(MfaPages::CHALLENGE_PATH, [
                $this->cookies->mfaChallenge($outcome->challenge),
                $this->cookies->expirePasswordless(),
            ]);
        }
        if ($outcome instanceof PasswordlessCodeRejected) {
            return $this->responder->page(
                $request,
                PasswordlessPages::code(
                    $outcome->prompt,
                    PasswordlessPages::INVALID_CODE,
                    StatusCodeInterface::STATUS_UNAUTHORIZED,
                ),
            );
        }
        if ($outcome->reason === PasswordlessFailure::Expired) {
            return $this->backToLogin();
        }

        // The code was right, and the sign-in still could not go ahead: the account is
        // disabled, or the application stopped signing people in by email.
        return $this->responder->page(
            $request,
            PasswordlessPages::failed($outcome->reason),
            [$this->cookies->expirePasswordless()],
        );
    }

    private function backToLogin(): ResponseInterface
    {
        return $this->responder->redirect('/auth/login', [$this->cookies->expirePasswordless()]);
    }
}
