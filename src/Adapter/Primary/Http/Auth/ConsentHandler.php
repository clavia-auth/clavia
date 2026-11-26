<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Auth;

use Clavia\Adapter\Primary\Http\OAuth2\OAuth2Responder;
use Clavia\Adapter\Primary\Http\Shared\Message;
use Clavia\Adapter\Primary\Http\Shared\RequestCookies;
use Clavia\Adapter\Primary\Http\Shared\RequestParameterReader;
use Clavia\Application\Authentication\EndUser;
use Clavia\Application\Authentication\RequireSignIn;
use Clavia\Application\Authentication\ResolveEndUser;
use Clavia\Application\OAuth2\Authorize\RequestRefused;
use Clavia\Application\OAuth2\Consent\ConsentGiven;
use Clavia\Application\OAuth2\Consent\DecideConsent;
use Clavia\Application\OAuth2\Consent\DescribeConsent;
use Clavia\Domain\Authentication\LocalPath;
use Fig\Http\Message\RequestMethodInterface;
use Fig\Http\Message\StatusCodeInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `GET|POST /auth/consent` — the screen that asks a signed-in person whether an
 * application may have what it asks for.
 *
 * Reached only from `/oauth2/authorize`, which puts the validated request on hold and
 * sends the browser here with its handle as `state`. The person must be the one who was
 * asked — signed in again if their session ended meanwhile, and coming back here
 * afterwards. The answer is a `POST` carrying the CSRF token; one without it re-renders
 * the screen, the request still on hold, so only the click is lost. Allowing sends the
 * browser back to the authorization request; refusing, to the application with
 * `access_denied`.
 */
final readonly class ConsentHandler implements RequestHandlerInterface
{
    public function __construct(
        private ResolveEndUser $resolveEndUser,
        private RequireSignIn $requireSignIn,
        private DescribeConsent $describe,
        private DecideConsent $decide,
        private AuthPageResponder $responder,
        private OAuth2Responder $oauth2,
        private AuthCookies $cookies,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $isPost = $request->getMethod() === RequestMethodInterface::METHOD_POST;
        $form = RequestParameterReader::form($request);
        $handle = ($isPost ? $form->get('state') : RequestParameterReader::query($request)->get('state')) ?? '';

        $endUser = ($this->resolveEndUser)(RequestCookies::first($request, $this->cookies->sessionCookieName));
        if ($endUser === null) {
            return $this->signInFirst($handle);
        }

        if (! $isPost) {
            return $this->question($request, $handle, $endUser);
        }
        if (! CsrfToken::isValid($request, $form->get('csrf_token'))) {
            return $this->question(
                $request,
                $handle,
                $endUser,
                Message::of(LoginPages::EXPIRED_FORM),
                StatusCodeInterface::STATUS_BAD_REQUEST,
            );
        }

        $outcome = ($this->decide)($handle, $endUser, $form->get('decision') === 'allow');
        if ($outcome instanceof ConsentGiven) {
            return $this->responder->redirect($outcome->resumeAt);
        }
        if ($outcome instanceof RequestRefused) {
            return $this->oauth2->redirectToClient($outcome->redirectUri, [
                'error' => $outcome->error->error->value,
                'error_description' => $outcome->error->description,
                'state' => $outcome->state,
            ]);
        }

        return $this->responder->page($request, ConsentPages::expired());
    }

    private function question(
        ServerRequestInterface $request,
        string $handle,
        EndUser $endUser,
        Message|string|null $error = null,
        int $status = StatusCodeInterface::STATUS_OK,
    ): ResponseInterface {
        $screen = $handle === '' ? null : ($this->describe)($handle, $endUser);
        if ($screen === null || $handle === '') {
            return $this->responder->page($request, ConsentPages::expired());
        }

        return $this->responder->page($request, ConsentPages::question($screen, $handle, $error, $status));
    }

    /** Nobody is signed in: sign in first, then come back to this very screen. */
    private function signInFirst(string $handle): ResponseInterface
    {
        $here = $handle === ''
            ? ConsentPages::PATH
            : ConsentPages::PATH . '?' . http_build_query(['state' => $handle], '', '&', PHP_QUERY_RFC3986);
        $loginState = ($this->requireSignIn)(LocalPath::fromString($here));

        return $this->responder->redirect(
            '/auth/login?' . http_build_query(['state' => $loginState], '', '&', PHP_QUERY_RFC3986),
        );
    }
}
