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
use Clavia\Application\Authentication\Account\CheckYourInbox;
use Clavia\Application\Authentication\Account\DescribeSignUpPage;
use Clavia\Application\Authentication\Account\SignUp;
use Clavia\Application\Authentication\Account\SignUpRefused;
use Clavia\Application\Authentication\Account\SignUpRequest;
use Clavia\Application\Authentication\SignIn\SecondFactorRequired;
use Fig\Http\Message\StatusCodeInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `GET|POST /auth/signup` — creating an account, from the login page of an authorization
 * request ({@see SignUp}).
 *
 * The GET shows the form when the application opens a pool to sign-ups, and says it does not
 * otherwise (`404`). The POST, with its CSRF token, either signs the new account in and
 * resumes the request, or answers "check your inbox"; a refusal re-renders the form with the
 * same handle.
 */
final readonly class SignUpHandler implements RequestHandlerInterface
{
    public function __construct(
        private DescribeSignUpPage $describe,
        private SignUp $signUp,
        private AuthPageResponder $responder,
        private AuthCookies $cookies,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        if ($request->getMethod() !== 'POST') {
            $loginState = RequestParameterReader::query($request)->get('state');

            return $this->form($request, $loginState);
        }

        $form = RequestParameterReader::form($request);
        $loginState = $form->get('state');
        $email = trim($form->get('email') ?? '');
        if (! CsrfToken::isValid($request, $form->get('csrf_token'))) {
            return $this->form(
                $request,
                $loginState,
                $email,
                LoginPages::EXPIRED_FORM,
                StatusCodeInterface::STATUS_BAD_REQUEST,
            );
        }

        $outcome = ($this->signUp)(new SignUpRequest(
            $email,
            $form->get('password') ?? '',
            $loginState,
            ClientAddress::of($request),
            RequestCookies::first($request, $this->cookies->sessionCookieName),
        ));
        if ($outcome instanceof CheckYourInbox) {
            return $this->responder->page($request, AccountPages::checkInbox($outcome->email, 'sign-up', $loginState));
        }
        if ($outcome instanceof SignUpRefused) {
            return $this->form(
                $request,
                $loginState,
                $outcome->email,
                AccountPages::signUpMessage($outcome->reason, $outcome->detail),
                AccountPages::signUpStatus($outcome->reason),
            );
        }
        if ($outcome instanceof SecondFactorRequired) {
            return $this->responder->redirect(
                MfaPages::CHALLENGE_PATH,
                [$this->cookies->mfaChallenge($outcome->challenge)],
            );
        }

        return $this->responder->redirect(
            $outcome->nextUrl,
            [$this->cookies->session($outcome->sessionId), $this->cookies->expireCsrf()],
        );
    }

    private function form(
        ServerRequestInterface $request,
        ?string $loginState,
        string $email = '',
        ?string $error = null,
        int $status = StatusCodeInterface::STATUS_OK,
    ): ResponseInterface {
        $page = ($this->describe)($loginState);
        if (! $page->available) {
            return $this->responder->page(
                $request,
                AccountPages::signUp(
                    $loginState,
                    [],
                    false,
                    $email,
                    AccountPages::SIGN_UP_UNAVAILABLE,
                    StatusCodeInterface::STATUS_NOT_FOUND,
                ),
            );
        }

        return $this->responder->page(
            $request,
            AccountPages::signUp($loginState, $page->formOrigins, $page->requiresVerification, $email, $error, $status),
        );
    }
}
