<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\Passwordless;

use Clavia\Application\Port\MailContent;
use Clavia\Application\Port\MailKind;
use Clavia\Application\Port\OutgoingMail;
use Clavia\Domain\Authentication\OneTimeCode;
use Clavia\Domain\Shared\Language;

/**
 * The passwordless sign-in emails: a six-digit code, or a link. What each carries, in the language it
 * is for; their words are the catalogue's (`mail.passwordless_*` in `translations/`).
 */
final readonly class SignInMail
{
    /** Where a sign-in link leads: a confirmation page, never a sign-in on GET. */
    public const string LINK_PATH = '/auth/passwordless/verify';

    /**
     * @param non-empty-string $site                What the person knows this server as: the root domain.
     * @param non-empty-string $issuer              The base URL links are built on.
     * @param positive-int     $codeLifetimeSeconds
     * @param positive-int     $linkLifetimeSeconds
     */
    public function __construct(
        private string $site,
        private string $issuer,
        private int $codeLifetimeSeconds,
        private int $linkLifetimeSeconds,
    ) {
    }

    /**
     * @param non-empty-string $email
     */
    public function code(string $email, OneTimeCode $code, Language $language): OutgoingMail
    {
        return new OutgoingMail(
            $email,
            new MailContent(
                MailKind::PasswordlessCode,
                ['site' => $this->site, 'code' => $code->value],
                $this->codeLifetimeSeconds,
            ),
            $language,
        );
    }

    /**
     * @param non-empty-string $email
     * @param non-empty-string $handle The link's secret.
     */
    public function link(string $email, #[\SensitiveParameter] string $handle, Language $language): OutgoingMail
    {
        return new OutgoingMail(
            $email,
            new MailContent(
                MailKind::PasswordlessLink,
                ['site' => $this->site, 'link' => $this->linkUrl($handle)],
                $this->linkLifetimeSeconds,
            ),
            $language,
        );
    }

    /**
     * @param non-empty-string $handle
     */
    public function linkUrl(#[\SensitiveParameter] string $handle): string
    {
        return rtrim($this->issuer, '/') . self::LINK_PATH . '?'
            . http_build_query(['token' => $handle], '', '&', PHP_QUERY_RFC3986);
    }
}
