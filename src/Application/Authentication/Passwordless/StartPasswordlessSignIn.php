<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\Passwordless;

use Clavia\Application\Authentication\EmailSendLimit;
use Clavia\Application\Authentication\SignIn\HeldSignInRequest;
use Clavia\Application\Authentication\SignIn\SignInRequestExpired;
use Clavia\Application\Connection\ConnectionAccess;
use Clavia\Application\Port\LoginStateStore;
use Clavia\Application\Port\Mailer;
use Clavia\Application\Port\MailUnavailable;
use Clavia\Application\Port\PasswordlessChallengeStore;
use Clavia\Domain\Authentication\LocalPath;
use Clavia\Domain\Authentication\OneTimeCode;
use Clavia\Domain\Authentication\PasswordlessChallenge;
use Clavia\Domain\Authentication\PasswordlessMode;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\Languages;
use Clavia\Domain\Shared\RandomSource;
use Clavia\Domain\Shared\SecretGenerator;

/**
 * Send a sign-in code or link to an address, and park the challenge it answers.
 *
 * In order: the request must name an address and a mode; the application behind the
 * login page's handle must let its users in by email ({@see ConnectionAccess}); the send
 * limit must allow one more message ({@see EmailSendLimit}). Only then is a
 * challenge opened and the message sent — and a message that cannot be sent leaves no
 * challenge behind.
 *
 * Whether the address has an account here changes nothing: one is created when the proof
 * comes back. So the answer never says whether someone is registered.
 */
final readonly class StartPasswordlessSignIn
{
    /**
     * @param positive-int $codeLifetimeSeconds `CLAVIA_PASSWORDLESS_CODE_LIFETIME`.
     * @param positive-int $linkLifetimeSeconds `CLAVIA_PASSWORDLESS_LINK_LIFETIME`.
     * @param Languages    $languages           What the mail's language is chosen among: the page's,
     *                                          else the default.
     */
    public function __construct(
        private ConnectionAccess $access,
        private ClientRepository $clients,
        private LoginStateStore $loginStates,
        private PasswordlessChallengeStore $challenges,
        private EmailSendLimit $sendLimit,
        private Mailer $mailer,
        private SignInMail $mail,
        private DescribePasswordlessChallenge $describe,
        private SecretGenerator $secrets,
        private RandomSource $random,
        private int $codeLifetimeSeconds,
        private int $linkLifetimeSeconds,
        private Languages $languages,
    ) {
    }

    public function __invoke(
        PasswordlessStart $request,
    ): PasswordlessCodeSent|PasswordlessLinkSent|PasswordlessRefused|SignInRequestExpired {
        $mode = PasswordlessMode::tryFrom($request->mode);
        try {
            $email = PasswordlessChallenge::address($request->email);
        } catch (InvalidValue) {
            $email = null;
        }
        if ($mode === null || $email === null) {
            return new PasswordlessRefused(PasswordlessFailure::InvalidRequest);
        }

        $loginState = $request->loginState === '' ? null : $request->loginState;
        // A request that is gone sends nothing: the code or link would sign in to nowhere.
        $target = HeldSignInRequest::find($this->loginStates, $loginState);
        if ($target instanceof SignInRequestExpired) {
            return $target;
        }
        $clientId = $target?->clientId;
        $client = $clientId === null ? null : $this->clients->find($clientId);
        if (! $this->access->allows($client, ConnectionName::email())) {
            return new PasswordlessRefused(PasswordlessFailure::NotAvailable);
        }

        if (! $this->sendLimit->allowOne($email, $request->clientAddress)) {
            return new PasswordlessRefused(PasswordlessFailure::TooManyEmails);
        }

        // Re-validated even though it came from this server's own store.
        $nextUrl = LocalPath::orDefault($target?->nextUrl)->value;
        $handle = $this->secrets->token();
        $language = $request->language !== null && $this->languages->has($request->language)
            ? $request->language
            : $this->languages->default;
        if ($mode === PasswordlessMode::Code) {
            $code = OneTimeCode::generate($this->random);
            $challenge = PasswordlessChallenge::forCode($email, $handle, $code, $nextUrl, $clientId, $loginState);
            $message = $this->mail->code($email, $code, $language);
            $lifetime = $this->codeLifetimeSeconds;
        } else {
            $challenge = PasswordlessChallenge::forLink($email, $nextUrl, $clientId, $loginState);
            $message = $this->mail->link($email, $handle, $language);
            $lifetime = $this->linkLifetimeSeconds;
        }

        $this->challenges->open($handle, $challenge, $lifetime);
        try {
            $this->mailer->send($message);
        } catch (MailUnavailable) {
            // Nobody will ever hold the proof for it.
            $this->challenges->claim($handle);

            return new PasswordlessRefused(PasswordlessFailure::MailUnavailable);
        }

        return $mode === PasswordlessMode::Code
            ? new PasswordlessCodeSent($handle, $this->describe->prompt($challenge))
            : new PasswordlessLinkSent($email);
    }
}
