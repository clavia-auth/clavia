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
use Clavia\Application\Authentication\EndUser;
use Clavia\Application\Authentication\Mfa\BeginTotpEnrollment;
use Clavia\Application\Authentication\Mfa\ConfirmTotpEnrollment;
use Clavia\Application\Authentication\Mfa\DescribeEnrolmentOnTheWay;
use Clavia\Application\Authentication\Mfa\DescribeMfa;
use Clavia\Application\Authentication\Mfa\DisableMfa;
use Clavia\Application\Authentication\Mfa\EnrolmentOnTheWay;
use Clavia\Application\Authentication\Mfa\FinishEnrolmentOnTheWay;
use Clavia\Application\Authentication\Mfa\ResumeTotpEnrollment;
use Clavia\Application\Authentication\Mfa\SecondFactors;
use Clavia\Application\Authentication\RequireSignIn;
use Clavia\Application\Authentication\ResolveEndUser;
use Clavia\Application\Port\EncryptionUnavailable;
use Clavia\Domain\Authentication\LocalPath;
use Clavia\Domain\Authentication\Mfa\FactorAlreadyConfirmed;
use LogicException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * The two-factor settings of the signed-in account:
 *
 * - `GET /auth/mfa/enroll` — whether it is on;
 * - `POST /auth/mfa/enroll` — start enrolling: a fresh seed, shown as a QR code. A POST,
 *   because it writes: a link that minted a seed whenever a browser prefetched it would
 *   be both surprising and wasteful;
 * - `POST /auth/mfa/enroll/confirm` — prove the app works, turn it on, show the
 *   recovery codes once;
 * - `POST /auth/mfa/disable` — turn it off;
 * - `POST /auth/mfa/enroll/continue` — back to the request that sent the person here.
 *
 * **On the way** (docs/design/mfa-policies.md §5.3), the pages carry the `state` of a request
 * requiring a second factor: they say who asks, confirming the app raises the session
 * ({@see FinishEnrolmentOnTheWay}), and the recovery codes lead back to the request.
 *
 * Every one needs a real session — the development auto-login does not count — and
 * sends a visitor without one to sign in first, coming back here afterwards. Every POST
 * carries the CSRF token; one that does not is sent back to the settings, unchanged.
 */
final readonly class MfaSettingsHandler implements RequestHandlerInterface
{
    public function __construct(
        private ResolveEndUser $resolveEndUser,
        private RequireSignIn $requireSignIn,
        private DescribeMfa $describe,
        private BeginTotpEnrollment $begin,
        private ResumeTotpEnrollment $resume,
        private ConfirmTotpEnrollment $confirm,
        private DisableMfa $disable,
        private DescribeEnrolmentOnTheWay $onTheWay,
        private FinishEnrolmentOnTheWay $finishOnTheWay,
        private AuthPageResponder $responder,
        private AuthCookies $cookies,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $endUser = ($this->resolveEndUser)->bySession(
            RequestCookies::first($request, $this->cookies->sessionCookieName),
        );
        if ($endUser === null) {
            $handle = ($this->requireSignIn)(LocalPath::fromString(MfaPages::SETTINGS_PATH));

            return $this->responder->redirect(
                '/auth/login?' . http_build_query(['state' => $handle], '', '&', PHP_QUERY_RFC3986),
            );
        }

        $path = $request->getUri()->getPath();
        if ($request->getMethod() !== 'POST') {
            $onTheWay = ($this->onTheWay)(RequestParameterReader::query($request)->get('state'));

            return $this->settings($request, $endUser, $onTheWay);
        }
        $form = RequestParameterReader::form($request);
        if (! CsrfToken::isValid($request, $form->get('csrf_token'))) {
            return $this->responder->redirect(MfaPages::SETTINGS_PATH);
        }
        $onTheWay = ($this->onTheWay)($form->get('state'));

        return match ($path) {
            MfaPages::SETTINGS_PATH => $this->begin($request, $endUser, $onTheWay),
            MfaPages::SETTINGS_PATH . '/confirm' => $this->confirm($request, $endUser, $onTheWay),
            MfaPages::CONTINUE_PATH => $this->responder->redirect(
                $this->onTheWay->resume($form->get('state')) ?? MfaPages::SETTINGS_PATH,
            ),
            '/auth/mfa/disable' => $this->disable($endUser),
            default => throw new LogicException('Routed to a path the handler does not serve.'),
        };
    }

    private function settings(
        ServerRequestInterface $request,
        EndUser $endUser,
        ?EnrolmentOnTheWay $onTheWay,
    ): ResponseInterface {
        $status = ($this->describe)($endUser->userId);

        return $status === null
            ? $this->responder->redirect('/auth/login')
            : $this->responder->page($request, MfaPages::settings($status, onTheWay: $onTheWay));
    }

    private function begin(
        ServerRequestInterface $request,
        EndUser $endUser,
        ?EnrolmentOnTheWay $onTheWay,
    ): ResponseInterface {
        try {
            $enrollment = ($this->begin)($endUser->userId);
        } catch (FactorAlreadyConfirmed) {
            // Already on: replacing it goes through turning it off first.
            return $this->responder->redirect(MfaPages::SETTINGS_PATH);
        } catch (EncryptionUnavailable) {
            $status = ($this->describe)($endUser->userId);

            return $status === null
                ? $this->responder->redirect('/auth/login')
                : $this->responder->page(
                    $request,
                    MfaPages::settings($status, MfaPages::ENCRYPTION_UNAVAILABLE, 503, $onTheWay),
                );
        }

        return $enrollment === null
            ? $this->responder->redirect('/auth/login')
            : $this->responder->page($request, MfaPages::setUp($enrollment, onTheWay: $onTheWay));
    }

    private function confirm(
        ServerRequestInterface $request,
        EndUser $endUser,
        ?EnrolmentOnTheWay $onTheWay,
    ): ResponseInterface {
        $codes = ($this->confirm)($endUser->userId, RequestParameterReader::form($request)->get('code') ?? '');
        if ($codes !== null) {
            // On the way, the app's first code was the second factor: the session is raised.
            $raised = $onTheWay === null ? null : ($this->finishOnTheWay)(
                RequestCookies::first($request, $this->cookies->sessionCookieName),
                $onTheWay->loginState,
                SecondFactors::APP,
            );

            return $this->responder->page(
                $request,
                MfaPages::recoveryCodes($codes, $onTheWay),
                $raised === null ? [] : [$this->cookies->session($raised)],
            );
        }

        // The same seed again rather than a new one, so a mistyped code does not cost a
        // second trip through the authenticator app.
        $enrollment = ($this->resume)($endUser->userId);

        return $enrollment === null
            ? $this->responder->redirect(MfaPages::SETTINGS_PATH)
            : $this->responder->page(
                $request,
                MfaPages::setUp($enrollment, MfaPages::INVALID_SETUP_CODE, 401, $onTheWay),
            );
    }

    private function disable(EndUser $endUser): ResponseInterface
    {
        ($this->disable)($endUser->userId);

        return $this->responder->redirect(MfaPages::SETTINGS_PATH);
    }
}
