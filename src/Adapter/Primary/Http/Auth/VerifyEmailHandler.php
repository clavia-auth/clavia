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
use Clavia\Application\Authentication\Account\ConfirmEmail;
use Clavia\Application\Authentication\Account\DescribeAccountLink;
use Clavia\Application\Authentication\Account\EmailConfirmed;
use Clavia\Domain\Identity\AccountLinkPurpose;
use Fig\Http\Message\RequestMethodInterface;
use Fig\Http\Message\StatusCodeInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `GET|POST /auth/verify-email` — where a verification link lands.
 *
 * The GET only asks, and spends nothing, so a mail scanner fetching the URL leaves the link
 * alive ({@see ConfirmEmail}). The POST from that page confirms the address, in whichever
 * browser opened the link, and leads to the login page. A link unknown, used, expired or no
 * longer matching its account gets `400`.
 */
final readonly class VerifyEmailHandler implements RequestHandlerInterface
{
    public function __construct(
        private DescribeAccountLink $describe,
        private ConfirmEmail $confirm,
        private AuthPageResponder $responder,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        if ($request->getMethod() !== RequestMethodInterface::METHOD_POST) {
            $token = RequestParameterReader::query($request)->get('token') ?? '';
            $email = ($this->describe)($token, AccountLinkPurpose::VerifyEmail);

            return $this->responder->page(
                $request,
                $email === null ? AccountPages::invalidLink() : AccountPages::confirmEmail($email, $token),
            );
        }

        $form = RequestParameterReader::form($request);
        $token = $form->get('token') ?? '';
        if (! CsrfToken::isValid($request, $form->get('csrf_token'))) {
            $email = ($this->describe)($token, AccountLinkPurpose::VerifyEmail);

            return $this->responder->page(
                $request,
                $email === null
                    ? AccountPages::invalidLink()
                    : AccountPages::confirmEmail(
                        $email,
                        $token,
                        LoginPages::EXPIRED_FORM,
                        StatusCodeInterface::STATUS_BAD_REQUEST,
                    ),
            );
        }

        $outcome = ($this->confirm)($token);

        return $this->responder->page(
            $request,
            $outcome instanceof EmailConfirmed
                ? AccountPages::emailVerified($outcome->email, $outcome->loginState)
                : AccountPages::invalidLink(),
        );
    }
}
