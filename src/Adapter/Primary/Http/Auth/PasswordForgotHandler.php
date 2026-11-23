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
use Clavia\Application\Authentication\Account\CheckYourInbox;
use Clavia\Application\Authentication\Account\RequestPasswordReset;
use Clavia\Application\Authentication\Account\ResetUnavailable;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `GET|POST /auth/password/forgot` — asking for a reset link ({@see RequestPasswordReset}).
 *
 * The answer to a well-formed address is always "check your email", whether or not it has an
 * account. The form is refused (`404`) where the application signs nobody in with a password
 * or this deployment cannot send mail.
 */
final readonly class PasswordForgotHandler implements RequestHandlerInterface
{
    public function __construct(
        private RequestPasswordReset $request,
        private AuthPageResponder $responder,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        if ($request->getMethod() !== 'POST') {
            return $this->responder->page(
                $request,
                AccountPages::forgot(RequestParameterReader::query($request)->get('state')),
            );
        }

        $form = RequestParameterReader::form($request);
        $loginState = $form->get('state');
        $email = trim($form->get('email') ?? '');
        if (! CsrfToken::isValid($request, $form->get('csrf_token'))) {
            return $this->responder->page(
                $request,
                AccountPages::forgot($loginState, $email, LoginPages::EXPIRED_FORM, 400),
            );
        }

        $outcome = ($this->request)($email, $loginState, ClientAddress::of($request));
        if ($outcome instanceof CheckYourInbox) {
            return $this->responder->page($request, AccountPages::checkInbox($outcome->email, 'reset', $loginState));
        }

        return $this->responder->page(
            $request,
            $outcome instanceof ResetUnavailable
                ? AccountPages::forgot($loginState, $email, AccountPages::RESET_UNAVAILABLE, 404)
                : AccountPages::forgot($loginState, $email, LoginPages::INVALID_EMAIL, 400),
        );
    }
}
