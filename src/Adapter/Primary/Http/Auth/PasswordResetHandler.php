<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Auth;

use Clavia\Adapter\Primary\Http\Shared\RequestParameterReader;
use Clavia\Application\Authentication\Account\DescribeAccountLink;
use Clavia\Application\Authentication\Account\PasswordChanged;
use Clavia\Application\Authentication\Account\PasswordRejected;
use Clavia\Application\Authentication\Account\ResetPassword;
use Clavia\Domain\Identity\AccountLinkPurpose;
use Fig\Http\Message\StatusCodeInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `GET|POST /auth/password/reset` — where a reset link lands.
 *
 * The GET shows the new-password form and spends nothing. The POST from it sets the password
 * ({@see ResetPassword}): every session of the account ends, so the browser's own session
 * cookie, if any, is dropped too, and the page leads to the login page. A refused password
 * keeps the link; a link unknown, used, expired or no longer matching gets `400`.
 */
final readonly class PasswordResetHandler implements RequestHandlerInterface
{
    public function __construct(
        private DescribeAccountLink $describe,
        private ResetPassword $reset,
        private AuthPageResponder $responder,
        private AuthCookies $cookies,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        if ($request->getMethod() !== 'POST') {
            $token = RequestParameterReader::query($request)->get('token') ?? '';
            $email = ($this->describe)($token, AccountLinkPurpose::ResetPassword);

            return $this->responder->page(
                $request,
                $email === null ? AccountPages::invalidLink() : AccountPages::resetForm($email, $token),
            );
        }

        $form = RequestParameterReader::form($request);
        $token = $form->get('token') ?? '';
        if (! CsrfToken::isValid($request, $form->get('csrf_token'))) {
            return $this->again($request, $token, LoginPages::EXPIRED_FORM);
        }

        $outcome = ($this->reset)($token, $form->get('password') ?? '');
        if ($outcome instanceof PasswordRejected) {
            return $this->again($request, $token, $outcome->detail);
        }
        if ($outcome instanceof PasswordChanged) {
            return $this->responder->page(
                $request,
                AccountPages::passwordChanged($outcome->email, $outcome->loginState),
                [$this->cookies->expireSession()],
            );
        }

        return $this->responder->page($request, AccountPages::invalidLink());
    }

    private function again(
        ServerRequestInterface $request,
        #[\SensitiveParameter] string $token,
        string $error,
    ): ResponseInterface {
        $email = ($this->describe)($token, AccountLinkPurpose::ResetPassword);

        return $this->responder->page(
            $request,
            $email === null ? AccountPages::invalidLink() : AccountPages::resetForm(
                $email,
                $token,
                $error,
                StatusCodeInterface::STATUS_BAD_REQUEST,
            ),
        );
    }
}
