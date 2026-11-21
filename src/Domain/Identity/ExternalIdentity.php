<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Identity;

use Clavia\Domain\Connection\ConnectionName;
use DateTimeImmutable;

/**
 * A Clavia account linked to an account at an external provider.
 *
 * The identity is `(provider, subject)` — the identifier the provider promises not to
 * reassign — and never the email address: addresses change hands, can be registered at
 * a provider by someone who does not own them, and are exactly what an attacker
 * controls. Once linked, the identity signs in as its account whatever address the
 * provider reports later.
 */
final readonly class ExternalIdentity
{
    /**
     * @param non-empty-string $subject
     * @param string|null      $email   The address the provider reported when the link was made.
     *                                  Informational — shown to operators — and never looked up.
     */
    private function __construct(
        public ConnectionName $provider,
        public string $subject,
        public UserId $userId,
        public ?string $email,
        public DateTimeImmutable $linkedAt,
    ) {
    }

    public static function link(AssertedIdentity $asserted, UserId $userId, DateTimeImmutable $now): self
    {
        return new self($asserted->provider, $asserted->subject, $userId, $asserted->email, $now);
    }

    /**
     * @param non-empty-string $subject
     */
    public static function reconstitute(
        ConnectionName $provider,
        string $subject,
        UserId $userId,
        ?string $email,
        DateTimeImmutable $linkedAt,
    ): self {
        return new self($provider, $subject, $userId, $email, $linkedAt);
    }
}
