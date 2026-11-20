<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Authentication;

use DateTimeImmutable;

/**
 * When and how the person behind a request authenticated, as far as this server knows:
 * what an ID token reports as `auth_time` and `amr` (OIDC Core §2).
 *
 * Captured when an authorization code is issued, from the session that approved it, and
 * carried by the code to the token endpoint — the session itself may be gone by then.
 * Unknown when nothing authenticated anyone (the development auto-login): an ID token
 * then leaves both claims out rather than claiming an authentication that never happened.
 */
final readonly class AuthenticationContext
{
    /**
     * @param list<AuthenticationMethod> $methods
     */
    private function __construct(
        public ?DateTimeImmutable $authenticatedAt,
        public array $methods,
    ) {
    }

    public static function fromSession(Session $session): self
    {
        return new self($session->authenticatedAt, $session->methods);
    }

    /** No authentication took place that this server could report. */
    public static function unknown(): self
    {
        return new self(null, []);
    }

    /**
     * Rebuild a context from storage.
     *
     * @param list<AuthenticationMethod> $methods
     */
    public static function reconstitute(?DateTimeImmutable $authenticatedAt, array $methods): self
    {
        return new self($authenticatedAt, array_values(array_unique($methods, SORT_REGULAR)));
    }

    /** @return list<string> The RFC 8176 `amr` values. */
    public function methodValues(): array
    {
        return array_map(static fn (AuthenticationMethod $method): string => $method->value, $this->methods);
    }
}
