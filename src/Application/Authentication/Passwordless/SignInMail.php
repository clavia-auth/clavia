<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);


namespace Clavia\Application\Authentication\Passwordless;

use Clavia\Application\Port\OutgoingMail;
use Clavia\Domain\Authentication\OneTimeCode;

/**
 * The words of the two sign-in emails.
 *
 * Plain text, short, and saying what the secret is good for and for how long: once, for
 * a few minutes. Each ends by telling someone who did not ask that ignoring it is safe —
 * which it is, since nothing happens until the code is typed or the link confirmed.
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
    public function code(string $email, OneTimeCode $code): OutgoingMail
    {
        return new OutgoingMail(
            $email,
            sprintf('Your sign-in code for %s', $this->site),
            sprintf(
                "Your sign-in code is %s\n\n"
                . "Type it into the page that asked for it. It works once and expires in %s.\n\n"
                . "If you did not ask for this, ignore this email.\n",
                $code->value,
                self::duration($this->codeLifetimeSeconds),
            ),
        );
    }

    /**
     * @param non-empty-string $email
     * @param non-empty-string $handle The link's secret.
     */
    public function link(string $email, #[\SensitiveParameter] string $handle): OutgoingMail
    {
        return new OutgoingMail(
            $email,
            sprintf('Sign in to %s', $this->site),
            sprintf(
                "Open this link to sign in:\n\n%s\n\n"
                . "It works once and expires in %s.\n\n"
                . "If you did not ask for this, ignore this email.\n",
                $this->linkUrl($handle),
                self::duration($this->linkLifetimeSeconds),
            ),
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

    /** Whole minutes, rounded up: a link valid for 90 seconds does not "expire in 1 minute". */
    private static function duration(int $seconds): string
    {
        $minutes = intdiv($seconds + 59, 60);

        return $minutes === 1 ? '1 minute' : $minutes . ' minutes';
    }
}
