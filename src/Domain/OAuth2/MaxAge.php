<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\OAuth2;

use DateTimeImmutable;

/**
 * The `max_age` of an authentication request (OpenID Connect Core §3.1.2.1): the most
 * seconds that may have passed since the person last actively authenticated. Older, and
 * they sign in again.
 *
 * `0` asks for an authentication now — the same as `prompt=login`, and, like it, dropped
 * from the request the login page sends the browser back to, or the fresh sign-in would
 * be too old a second later. Any other value stays: a fresh sign-in satisfies it.
 */
final readonly class MaxAge
{
    /**
     * @param non-negative-int $seconds
     */
    private function __construct(public int $seconds)
    {
    }

    /**
     * @param string|null $parameter The parameter as received; null when absent.
     *
     * @throws OAuth2Error When it is not a non-negative whole number of seconds.
     */
    public static function fromParameter(?string $parameter): ?self
    {
        if ($parameter === null) {
            return null;
        }
        if (preg_match('/^(0|[1-9][0-9]{0,9})$/D', $parameter) !== 1) {
            throw OAuth2Error::invalidRequest("'max_age' must be a non-negative whole number of seconds.");
        }

        return new self(max(0, (int) $parameter));
    }

    public function isZero(): bool
    {
        return $this->seconds === 0;
    }

    /**
     * Whether an authentication at `$authenticatedAt` is too old for this request. An
     * unknown time — the development auto-login — cannot satisfy any `max_age`: a time
     * nobody knows is not recent. Counted in whole seconds, like the `auth_time` claim it
     * is compared with: a sign-in this second is not "older than 0" for its milliseconds.
     */
    public function isExceededBy(?DateTimeImmutable $authenticatedAt, DateTimeImmutable $now): bool
    {
        if ($this->seconds === 0 || $authenticatedAt === null) {
            return true;
        }

        return $now->getTimestamp() - $authenticatedAt->getTimestamp() > $this->seconds;
    }
}
