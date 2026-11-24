<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Auth;

use Clavia\Adapter\Primary\Http\Shared\ErrorResponder;
use Clavia\Adapter\Primary\Http\Shared\RequestCookies;
use Clavia\Adapter\Primary\Http\Shared\RequestParameterReader;
use Clavia\Application\Authentication\External\CompleteExternalSignIn;
use Clavia\Application\Authentication\External\ExternalCallback;
use Clavia\Application\Authentication\External\ExternalSignInRefused;
use Clavia\Application\Authentication\LoginPage\DescribeLoginPage;
use Clavia\Application\Authentication\SignIn\SecondFactorRequired;
use Fig\Http\Message\StatusCodeInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `GET /auth/social/{provider}/callback` — the provider's redirect back (RFC 6749 §4.1.2).
 *
 * Whatever happens, the `state` cookie is spent. A refusal shows the ordinary sign-in
 * form, as if reached directly, with this server's own sentence for why
 * ({@see ExternalSignInMessages}): nothing from this request's query string reaches the
 * page, not even the theme toggle's return address.
 */
final readonly class ExternalSignInCallbackHandler implements RequestHandlerInterface
{
    public function __construct(
        private CompleteExternalSignIn $complete,
        private DescribeLoginPage $describe,
        private AuthPageResponder $responder,
        private ErrorResponder $errors,
        private AuthCookies $cookies,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $query = RequestParameterReader::query($request);
        $outcome = ($this->complete)(new ExternalCallback(
            ExternalSignInHandler::provider($request),
            $query->isRepeated('code') ? null : $query->get('code'),
            $query->isRepeated('state') ? null : $query->get('state'),
            $query->get('error') !== null || $query->isRepeated('error'),
            RequestCookies::first($request, AuthCookies::EXTERNAL_SIGN_IN),
            RequestCookies::first($request, $this->cookies->sessionCookieName),
        ));

        if ($outcome === null) {
            return $this->errors->notFound($request);
        }
        if ($outcome instanceof ExternalSignInRefused) {
            return $this->responder
                ->page($request, LoginPages::form(
                    null,
                    [],
                    $this->describe->methods(null),
                    null,
                    ExternalSignInMessages::for($outcome),
                    StatusCodeInterface::STATUS_BAD_REQUEST,
                ))
                ->withAddedHeader('Set-Cookie', $this->cookies->expireExternalSignIn()->toString());
        }
        if ($outcome instanceof SecondFactorRequired) {
            return $this->responder->redirect(MfaPages::CHALLENGE_PATH, [
                $this->cookies->mfaChallenge($outcome->challenge),
                $this->cookies->expireExternalSignIn(),
            ]);
        }

        return $this->responder->redirect($outcome->nextUrl, [
            $this->cookies->session($outcome->sessionId),
            $this->cookies->expireExternalSignIn(),
        ]);
    }
}
