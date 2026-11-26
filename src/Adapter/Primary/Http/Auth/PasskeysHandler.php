<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Auth;

use Clavia\Adapter\Primary\Http\Shared\HtmlPage;
use Clavia\Adapter\Primary\Http\Shared\Message;
use Clavia\Adapter\Primary\Http\Shared\RequestCookies;
use Clavia\Adapter\Primary\Http\Shared\RequestParameterReader;
use Clavia\Application\Authentication\Mfa\DescribeEnrolmentOnTheWay;
use Clavia\Application\Authentication\Mfa\EnrolmentOnTheWay;
use Clavia\Application\Authentication\Passkey\BeginPasskeyRegistration;
use Clavia\Application\Authentication\Passkey\CompletePasskeyRegistration;
use Clavia\Application\Authentication\Passkey\DescribePasskeys;
use Clavia\Application\Authentication\Passkey\PasskeyAdded;
use Clavia\Application\Authentication\Passkey\PasskeyChange;
use Clavia\Application\Authentication\Passkey\PasskeyLimitReached;
use Clavia\Application\Authentication\Passkey\PasskeyNotAdded;
use Clavia\Application\Authentication\Passkey\RemovePasskey;
use Clavia\Application\Authentication\Passkey\RenamePasskey;
use Clavia\Application\Authentication\Passkey\SignInAgain;
use Clavia\Application\Authentication\RequireSignIn;
use Clavia\Application\Authentication\ResolveEndUser;
use Clavia\Domain\Authentication\LocalPath;
use Clavia\Domain\Authentication\Session;
use Fig\Http\Message\RequestMethodInterface;
use Fig\Http\Message\StatusCodeInterface;
use LogicException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * The passkeys of the signed-in account (docs/design/passkeys.md §6.1, §6.4):
 *
 * - `GET /auth/passkeys`: the account's passkeys;
 * - `POST /auth/passkeys/new`: open a registration ceremony, and show the page where the browser
 *   makes the passkey. A POST, because it writes: nothing is opened by a prefetch;
 * - `POST /auth/passkeys`: the browser's answer, which becomes a passkey or does not;
 * - `POST /auth/passkeys/{passkey_id}/name` and `…/remove`.
 *
 * Every one needs a real session (the development auto-login does not count), and every change
 * one signed in recently: a visitor without either is sent to sign in, and comes back here. Every
 * POST carries the CSRF token; one that does not is sent back to the list, unchanged. With
 * `CLAVIA_PASSKEYS_ENABLED=false` none of it is routed.
 *
 * **On the way** to an application requiring a second factor (docs/design/mfa-policies.md §5.3),
 * making a passkey carries the held request's `state`, and once it is made the browser goes back
 * to that request — past the recovery codes, when the passkey brought some — where the step-up
 * asks for it. The sign-in needed for making one recently is still needed.
 */
final readonly class PasskeysHandler implements RequestHandlerInterface
{
    public function __construct(
        private ResolveEndUser $resolveEndUser,
        private RequireSignIn $requireSignIn,
        private DescribePasskeys $describe,
        private BeginPasskeyRegistration $begin,
        private CompletePasskeyRegistration $complete,
        private RenamePasskey $rename,
        private RemovePasskey $remove,
        private DescribeEnrolmentOnTheWay $onTheWay,
        private AuthPageResponder $responder,
        private AuthCookies $cookies,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $session = ($this->resolveEndUser)->bySession(
            RequestCookies::first($request, $this->cookies->sessionCookieName),
        )?->session;
        if ($session === null) {
            return $this->signInFirst();
        }

        if ($request->getMethod() !== RequestMethodInterface::METHOD_POST) {
            return $this->list($request, $session);
        }
        $form = RequestParameterReader::form($request);
        if (! CsrfToken::isValid($request, $form->get('csrf_token'))) {
            return $this->responder->redirect(PasskeyPages::PATH);
        }
        /** @var mixed $passkeyId */
        $passkeyId = $request->getAttribute('passkey_id');
        $path = $request->getUri()->getPath();

        $onTheWay = ($this->onTheWay)($form->get('state'));

        return match (true) {
            $path === PasskeyPages::PATH . '/new' => $this->begin($request, $session, $onTheWay),
            $path === PasskeyPages::PATH => $this->complete(
                $request,
                $session,
                $form->get('credential') ?? '',
                $form->get('name') ?? '',
                $onTheWay,
            ),
            is_string($passkeyId) && str_ends_with($path, '/name') => $this->changed(
                $request,
                $session,
                ($this->rename)($session, $passkeyId, $form->get('name') ?? ''),
            ),
            is_string($passkeyId) && str_ends_with($path, '/remove') => $this->changed(
                $request,
                $session,
                ($this->remove)($session, $passkeyId),
            ),
            default => throw new LogicException('Routed to a path the handler does not serve.'),
        };
    }

    private function list(
        ServerRequestInterface $request,
        Session $session,
        ?Message $error = null,
        int $status = StatusCodeInterface::STATUS_OK,
    ): ResponseInterface {
        $passkeys = ($this->describe)($session->userId);

        return $passkeys === null
            ? $this->responder->redirect('/auth/login')
            : $this->responder->page($request, PasskeyPages::list($passkeys, $error, $status));
    }

    private function begin(
        ServerRequestInterface $request,
        Session $session,
        ?EnrolmentOnTheWay $onTheWay,
    ): ResponseInterface {
        $options = ($this->begin)($session);

        return match (true) {
            $options === null => $this->responder->redirect('/auth/login'),
            $options instanceof SignInAgain => $this->signInFirst(),
            $options instanceof PasskeyLimitReached => $this->list(
                $request,
                $session,
                self::limit($options),
                StatusCodeInterface::STATUS_CONFLICT,
            ),
            default => $this->responder->page(
                $request,
                PasskeyPages::create($options, onTheWay: $onTheWay),
                [$this->cookies->webauthn($options->handle)],
            ),
        };
    }

    private function complete(
        ServerRequestInterface $request,
        Session $session,
        string $credential,
        string $name,
        ?EnrolmentOnTheWay $onTheWay,
    ): ResponseInterface {
        $handle = RequestCookies::first($request, AuthCookies::WEBAUTHN) ?? '';
        $outcome = ($this->complete)($session, $handle, $credential, $name);
        $spent = [$this->cookies->expireWebAuthn()];

        return match (true) {
            $outcome instanceof SignInAgain => $this->signInFirst(),
            $outcome instanceof PasskeyLimitReached => $this->list(
                $request,
                $session,
                self::limit($outcome),
                StatusCodeInterface::STATUS_CONFLICT,
            ),
            $outcome instanceof PasskeyAdded => $outcome->recoveryCodes === null
                ? $this->responder->redirect(
                    $onTheWay === null
                        ? PasskeyPages::PATH
                        : $this->onTheWay->resume($onTheWay->loginState) ?? PasskeyPages::PATH,
                    $spent,
                )
                : $this->responder->page(
                    $request,
                    PasskeyPages::recoveryCodes($outcome->recoveryCodes, $onTheWay),
                    $spent,
                ),
            default => $this->responder->page(
                $request,
                $this->failurePage($session, $outcome),
                $spent,
            ),
        };
    }

    private function failurePage(Session $session, PasskeyNotAdded $outcome): HtmlPage
    {
        $passkeys = ($this->describe)($session->userId);
        if ($passkeys === null) {
            throw new LogicException('A session whose account is gone was resolved.');
        }

        return PasskeyPages::list(
            $passkeys,
            match ($outcome) {
                PasskeyNotAdded::AlreadyRegistered => Message::of(PasskeyPages::ALREADY_REGISTERED),
                PasskeyNotAdded::InvalidName => Message::of(PasskeyPages::INVALID_NAME),
                PasskeyNotAdded::CeremonyGone, PasskeyNotAdded::Rejected => Message::of(PasskeyPages::START_AGAIN),
            },
            StatusCodeInterface::STATUS_BAD_REQUEST,
        );
    }

    private function changed(
        ServerRequestInterface $request,
        Session $session,
        PasskeyChange|SignInAgain $outcome,
    ): ResponseInterface {
        return match ($outcome) {
            PasskeyChange::Done => $this->responder->redirect(PasskeyPages::PATH),
            PasskeyChange::NotFound => $this->list(
                $request,
                $session,
                Message::of(PasskeyPages::NOT_FOUND),
                StatusCodeInterface::STATUS_NOT_FOUND,
            ),
            PasskeyChange::InvalidName => $this->list(
                $request,
                $session,
                Message::of(PasskeyPages::INVALID_NAME),
                StatusCodeInterface::STATUS_BAD_REQUEST,
            ),
            PasskeyChange::LastWayIn => $this->list(
                $request,
                $session,
                Message::of(PasskeyPages::LAST_WAY_IN),
                StatusCodeInterface::STATUS_CONFLICT,
            ),
            default => $this->signInFirst(),
        };
    }

    /** To the login page, holding this page as where to come back to. */
    private function signInFirst(): ResponseInterface
    {
        $handle = ($this->requireSignIn)(LocalPath::fromString(PasskeyPages::PATH));

        return $this->responder->redirect(
            '/auth/login?' . http_build_query(['state' => $handle], '', '&', PHP_QUERY_RFC3986),
        );
    }

    private static function limit(PasskeyLimitReached $reached): Message
    {
        return Message::of('passkeys.error.limit', ['limit' => $reached->limit]);
    }
}
