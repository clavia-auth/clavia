<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Auth\Saml;

use Clavia\Adapter\Primary\Http\Auth\AuthCookies;
use Clavia\Adapter\Primary\Http\Auth\AuthPageResponder;
use Clavia\Adapter\Primary\Http\Auth\ExternalSignInMessages;
use Clavia\Adapter\Primary\Http\Auth\LoginPages;
use Clavia\Adapter\Primary\Http\Auth\MfaPages;
use Clavia\Adapter\Primary\Http\Shared\ErrorResponder;
use Clavia\Adapter\Primary\Http\Shared\RequestCookies;
use Clavia\Adapter\Primary\Http\Shared\RequestParameterReader;
use Clavia\Application\Authentication\External\ExternalSignInRefused;
use Clavia\Application\Authentication\External\Saml\CompleteSamlSignIn;
use Clavia\Application\Authentication\External\Saml\SamlCallback;
use Clavia\Application\Authentication\LoginPage\DescribeLoginPage;
use Clavia\Application\Authentication\SignIn\SecondFactorRequired;
use Fig\Http\Message\StatusCodeInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;
use Psr\Log\LoggerInterface;

/**
 * `GET /auth/saml/{connection}/complete`: where the assertion consumer service sends the browser, now
 * with its cookies, for every check of the sign-in. A refusal is the external sign-in's page, the same
 * for every reason; the log keeps the category, never what the identity provider sent.
 */
final readonly class SamlCompleteHandler implements RequestHandlerInterface
{
    public function __construct(
        private CompleteSamlSignIn $complete,
        private DescribeLoginPage $describe,
        private AuthPageResponder $responder,
        private ErrorResponder $errors,
        private AuthCookies $cookies,
        private LoggerInterface $logger,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $query = RequestParameterReader::query($request);
        $connection = SamlSignInHandler::connection($request);
        $outcome = ($this->complete)(new SamlCallback(
            $connection,
            $query->isRepeated('h') ? null : $query->get('h'),
            RequestCookies::first($request, AuthCookies::EXTERNAL_SIGN_IN),
            RequestCookies::first($request, $this->cookies->sessionCookieName),
        ));

        if ($outcome === null) {
            return $this->errors->notFound($request);
        }
        if ($outcome instanceof ExternalSignInRefused) {
            $this->logger->notice('A SAML sign-in through {connection} was refused: {reason} ({category}).', [
                'connection' => $connection,
                'reason' => $outcome->reason->name,
                'category' => $outcome->category ?? '-',
            ]);

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
