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
use Clavia\Application\Authentication\Passwordless\DescribePasswordlessChallenge;
use Clavia\Application\Authentication\Passwordless\FollowPasswordlessLink;
use Clavia\Application\Authentication\Passwordless\PasswordlessFailure;
use Clavia\Application\Authentication\SignIn\SecondFactorRequired;
use Clavia\Application\Authentication\SignIn\SignedIn;
use Clavia\Domain\Authentication\PasswordlessMode;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `GET|POST /auth/passwordless/verify` — where a sign-in link lands.
 *
 * The GET only asks: it shows which address the link signs in as, and spends nothing, so
 * a mail scanner fetching the URL leaves the link alive ({@see FollowPasswordlessLink}).
 * The POST from that page signs in, in whichever browser opened the link. A link unknown,
 * used or expired gets `400`.
 */
final readonly class PasswordlessLinkHandler implements RequestHandlerInterface
{
    public function __construct(
        private DescribePasswordlessChallenge $describe,
        private FollowPasswordlessLink $follow,
        private AuthPageResponder $responder,
        private AuthCookies $cookies,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        if ($request->getMethod() !== 'POST') {
            $token = RequestParameterReader::query($request)->get('token') ?? '';
            $prompt = ($this->describe)($token, PasswordlessMode::Link);

            return $prompt === null
                ? $this->responder->page($request, PasswordlessPages::failed(PasswordlessFailure::InvalidLink))
                : $this->responder->page($request, PasswordlessPages::linkConfirm($prompt, $token));
        }

        $form = RequestParameterReader::form($request);
        $token = $form->get('token') ?? '';
        if (! CsrfToken::isValid($request, $form->get('csrf_token'))) {
            $prompt = ($this->describe)($token, PasswordlessMode::Link);

            return $this->responder->page(
                $request,
                $prompt === null
                    ? PasswordlessPages::failed(PasswordlessFailure::InvalidLink)
                    : PasswordlessPages::linkConfirm($prompt, $token, LoginPages::EXPIRED_FORM, 400),
            );
        }

        $outcome = ($this->follow)($token, RequestCookies::first($request, $this->cookies->sessionCookieName));

        if ($outcome instanceof SignedIn) {
            return $this->responder->redirect(
                $outcome->nextUrl,
                [$this->cookies->session($outcome->sessionId), $this->cookies->expireCsrf()],
            );
        }
        if ($outcome instanceof SecondFactorRequired) {
            return $this->responder->redirect(
                MfaPages::CHALLENGE_PATH,
                [$this->cookies->mfaChallenge($outcome->challenge)],
            );
        }

        return $this->responder->page($request, PasswordlessPages::failed($outcome->reason));
    }
}
