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
use Clavia\Adapter\Primary\Http\Shared\Message;
use Clavia\Adapter\Primary\Http\Shared\RequestCookies;
use Clavia\Adapter\Primary\Http\Shared\RequestParameterReader;
use Clavia\Application\Authentication\EndUser;
use Clavia\Application\Authentication\RequireSignIn;
use Clavia\Application\Authentication\ResolveEndUser;
use Clavia\Application\OAuth2\Device\DecideDeviceRequest;
use Clavia\Application\OAuth2\Device\DescribeDeviceRequest;
use Clavia\Application\OAuth2\Device\DeviceSignInRequired;
use Clavia\Application\OAuth2\Device\DeviceStrongerSignInRequired;
use Clavia\Application\OAuth2\Device\UserCodeThrottle;
use Clavia\Domain\Authentication\LocalPath;
use Clavia\Domain\Client\ClientId;
use Fig\Http\Message\RequestMethodInterface;
use Fig\Http\Message\StatusCodeInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `GET|POST /auth/device` — where a person approves a device that cannot sign in itself
 * (RFC 8628 §3.3).
 *
 * The device showed a short code and this address. The person, signed in here on a
 * machine with a browser, types the code — or follows `verification_uri_complete`, which
 * carries it — sees which application asks and for what, and allows or refuses. The
 * user code is the only thing about the request this page's URL or form carries: it is
 * made to be typed, and worth nothing without a session here.
 */
final readonly class DeviceHandler implements RequestHandlerInterface
{
    public function __construct(
        private ResolveEndUser $resolveEndUser,
        private RequireSignIn $requireSignIn,
        private DescribeDeviceRequest $describe,
        private DecideDeviceRequest $decide,
        private AuthPageResponder $responder,
        private AuthCookies $cookies,
        private UserCodeThrottle $throttle,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $isPost = $request->getMethod() === RequestMethodInterface::METHOD_POST;
        $form = RequestParameterReader::form($request);
        $typed = ($isPost ? $form->get('user_code') : RequestParameterReader::query($request)->get('user_code')) ?? '';

        $endUser = ($this->resolveEndUser)(RequestCookies::first($request, $this->cookies->sessionCookieName));
        if ($endUser === null) {
            return $this->signInFirst($typed === '' || $isPost ? DevicePages::PATH : DevicePages::address($typed));
        }

        if ($isPost && ! CsrfToken::isValid($request, $form->get('csrf_token'))) {
            return $this->responder->page(
                $request,
                DevicePages::entry(
                    $typed,
                    Message::of(LoginPages::EXPIRED_FORM),
                    StatusCodeInterface::STATUS_BAD_REQUEST,
                ),
            );
        }
        if ($typed === '') {
            return $this->responder->page($request, DevicePages::entry());
        }
        if ($this->throttle->isThrottled($endUser->userId, ClientAddress::of($request))) {
            return $this->responder->page(
                $request,
                DevicePages::entry(
                    $typed,
                    Message::of(DevicePages::TOO_MANY_CODES),
                    StatusCodeInterface::STATUS_TOO_MANY_REQUESTS,
                ),
            );
        }

        $decision = $isPost ? $form->get('decision') : null;
        if ($decision !== 'allow' && $decision !== 'deny') {
            return $this->review($request, $typed, $endUser);
        }

        $outcome = ($this->decide)($typed, $endUser, $decision === 'allow');
        if ($outcome === null) {
            return $this->invalid($request, $typed, $endUser);
        }
        if ($outcome instanceof DeviceSignInRequired) {
            return $this->signInFirst(DevicePages::address($outcome->userCode), $outcome->clientId);
        }
        if ($outcome instanceof DeviceStrongerSignInRequired) {
            return $this->strongerSignIn($request, $typed, $outcome);
        }

        return $this->responder->page($request, DevicePages::done($outcome->approved, $outcome->noPermission));
    }

    private function review(ServerRequestInterface $request, string $typed, EndUser $endUser): ResponseInterface
    {
        $review = ($this->describe)($typed, $endUser);

        return $review === null
            ? $this->invalid($request, $typed, $endUser)
            : $this->responder->page($request, DevicePages::review($review));
    }

    /** A code that stands for nothing: said so, and counted against whoever typed it. */
    private function invalid(ServerRequestInterface $request, string $typed, EndUser $endUser): ResponseInterface
    {
        $this->throttle->recordMiss($endUser->userId, ClientAddress::of($request));

        return $this->responder->page(
            $request,
            DevicePages::entry($typed, Message::of(DevicePages::INVALID_CODE), StatusCodeInterface::STATUS_BAD_REQUEST),
        );
    }

    /**
     * The application or its API requires more than one factor: one more on the second-factor
     * page, or one set up on the way, and back to this code; or, with neither possible, said so
     * and the request left pending.
     */
    private function strongerSignIn(
        ServerRequestInterface $request,
        string $typed,
        DeviceStrongerSignInRequired $outcome,
    ): ResponseInterface {
        if ($outcome->stepUp !== null) {
            return $this->responder->redirect(
                MfaPages::CHALLENGE_PATH,
                [$this->cookies->mfaChallenge($outcome->stepUp)],
            );
        }
        if ($outcome->enrolment !== null) {
            return $this->responder->redirect(
                MfaPages::SETTINGS_PATH . '?' . http_build_query(['state' => $outcome->enrolment]),
            );
        }

        return $this->responder->page(
            $request,
            DevicePages::entry(
                $typed,
                Message::of(DevicePages::STRONGER_SIGN_IN),
                StatusCodeInterface::STATUS_FORBIDDEN,
            ),
        );
    }

    private function signInFirst(string $returnTo, ?ClientId $for = null): ResponseInterface
    {
        $loginState = ($this->requireSignIn)(LocalPath::fromString($returnTo), $for);

        return $this->responder->redirect(
            '/auth/login?' . http_build_query(['state' => $loginState], '', '&', PHP_QUERY_RFC3986),
        );
    }
}
