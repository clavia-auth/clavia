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
use Clavia\Application\Authentication\Passwordless\PasswordlessFailure;
use Clavia\Application\Authentication\Passwordless\PasswordlessPrompt;
use Fig\Http\Message\StatusCodeInterface;

/**
 * The pages of a passwordless sign-in: where the code is typed, and the link's three
 * stages — sent, confirm, failed — and the words for each way it can go wrong.
 */
final class PasswordlessPages
{
    public const string CODE_PATH = '/auth/passwordless/code';

    public const string INVALID_CODE = 'passwordless.error.invalid_code';

    public const string INVALID_LINK = 'passwordless.error.invalid_link';

    public const string ACCOUNT_DISABLED = 'passwordless.error.account_disabled';

    private function __construct()
    {
    }

    public static function code(
        PasswordlessPrompt $prompt,
        ?Message $error = null,
        int $status = StatusCodeInterface::STATUS_OK,
    ): HtmlPage {
        return new HtmlPage(
            template: 'auth::passwordless-code',
            title: Message::of('account.check_inbox.title'),
            heading: Message::of('account.check_inbox.title'),
            returnTo: self::CODE_PATH,
            variables: ['email' => $prompt->email],
            error: $error,
            status: $status,
            formOrigins: $prompt->formOrigins,
        );
    }

    /**
     * @param non-empty-string $email
     */
    public static function linkSent(string $email): HtmlPage
    {
        return new HtmlPage(
            template: 'auth::passwordless-link',
            title: Message::of('account.check_inbox.title'),
            heading: Message::of('account.check_inbox.title'),
            returnTo: '/auth/login',
            variables: ['stage' => 'sent', 'email' => $email, 'token' => ''],
        );
    }

    /**
     * The question a link opens on. Its address carries the token, which is why it is
     * rebuilt here — the theme toggle comes back to it — and why the page sends no
     * `Referer` beyond this origin.
     */
    public static function linkConfirm(
        PasswordlessPrompt $prompt,
        #[\SensitiveParameter] string $token,
        ?Message $error = null,
        int $status = StatusCodeInterface::STATUS_OK,
    ): HtmlPage {
        return new HtmlPage(
            template: 'auth::passwordless-link',
            title: Message::of('login.title'),
            heading: Message::of('passwordless.confirm.heading'),
            returnTo: self::linkAddress($token),
            variables: ['stage' => 'confirm', 'email' => $prompt->email, 'token' => $token],
            error: $error,
            status: $status,
            formOrigins: $prompt->formOrigins,
        );
    }

    /**
     * A sign-in that cannot go on from here: the person asks for a new code or link.
     */
    public static function failed(PasswordlessFailure $reason): HtmlPage
    {
        return new HtmlPage(
            template: 'auth::passwordless-link',
            title: Message::of('passwordless.failed.title'),
            heading: $reason === PasswordlessFailure::InvalidLink
                ? Message::of('account.invalid_link.title')
                : Message::of('passwordless.failed.heading'),
            returnTo: '/auth/login',
            variables: ['stage' => 'failed', 'email' => '', 'token' => ''],
            error: self::message($reason),
            status: self::status($reason),
        );
    }

    /** What the person is told, for every way a passwordless sign-in can stop. */
    public static function message(PasswordlessFailure $reason): Message
    {
        return match ($reason) {
            PasswordlessFailure::InvalidRequest => Message::of(LoginPages::INVALID_EMAIL),
            PasswordlessFailure::NotAvailable => Message::of(LoginPages::EMAIL_UNAVAILABLE),
            PasswordlessFailure::TooManyEmails => Message::of(LoginPages::TOO_MANY_EMAILS),
            PasswordlessFailure::MailUnavailable => Message::of(LoginPages::MAIL_UNAVAILABLE),
            PasswordlessFailure::Expired, PasswordlessFailure::InvalidLink => Message::of(self::INVALID_LINK),
            PasswordlessFailure::AccountDisabled => Message::of(self::ACCOUNT_DISABLED),
        };
    }

    public static function status(PasswordlessFailure $reason): int
    {
        return match ($reason) {
            PasswordlessFailure::TooManyEmails => StatusCodeInterface::STATUS_TOO_MANY_REQUESTS,
            PasswordlessFailure::MailUnavailable => StatusCodeInterface::STATUS_SERVICE_UNAVAILABLE,
            PasswordlessFailure::AccountDisabled => StatusCodeInterface::STATUS_FORBIDDEN,
            PasswordlessFailure::InvalidRequest,
            PasswordlessFailure::NotAvailable,
            PasswordlessFailure::Expired,
            PasswordlessFailure::InvalidLink => StatusCodeInterface::STATUS_BAD_REQUEST,
        };
    }

    public static function linkAddress(#[\SensitiveParameter] string $token): string
    {
        return '/auth/passwordless/verify?' . http_build_query(['token' => $token], '', '&', PHP_QUERY_RFC3986);
    }
}
