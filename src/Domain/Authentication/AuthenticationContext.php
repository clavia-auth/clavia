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
 * what an ID token reports as `auth_time` and `amr` (OIDC Core §2), and the session that
 * witnessed it — its `sid` (Back-Channel Logout 1.0 §2.1).
 *
 * Captured when an authorization code is issued, from the session that approved it, and
 * carried by the code to the token endpoint — the session itself may be gone by then.
 * Unknown when nothing authenticated anyone (the development auto-login): an ID token
 * then leaves the claims out rather than claiming an authentication that never happened,
 * or naming a session that does not exist.
 */
final readonly class AuthenticationContext
{
    /**
     * @param list<AuthenticationMethod> $methods
     * @param non-empty-string|null      $sid     The session's identifier for relying parties; null when
     *                                            no session stands behind the authentication.
     */
    private function __construct(
        public ?DateTimeImmutable $authenticatedAt,
        public array $methods,
        public ?string $sid,
    ) {
    }

    public static function fromSession(Session $session): self
    {
        return new self($session->authenticatedAt, $session->methods, $session->sid);
    }

    /** No authentication took place that this server could report. */
    public static function unknown(): self
    {
        return new self(null, [], null);
    }

    /**
     * Rebuild a context from storage.
     *
     * @param list<AuthenticationMethod> $methods
     */
    public static function reconstitute(?DateTimeImmutable $authenticatedAt, array $methods, ?string $sid = null): self
    {
        return new self(
            $authenticatedAt,
            array_values(array_unique($methods, SORT_REGULAR)),
            $sid === null || $sid === '' ? null : $sid,
        );
    }

    /**
     * The same authentication, told to no session: what a device approved on another
     * screen carries. The device holds no session of its own here, so there is nothing a
     * relying party could later be told has ended.
     */
    public function withoutSession(): self
    {
        return new self($this->authenticatedAt, $this->methods, null);
    }

    /** @return list<string> The RFC 8176 `amr` values. */
    public function methodValues(): array
    {
        return array_map(static fn (AuthenticationMethod $method): string => $method->value, $this->methods);
    }
}
