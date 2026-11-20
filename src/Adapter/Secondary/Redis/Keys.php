<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Redis;

use Clavia\Domain\Shared\Digest;

/**
 * How Redis keys are named: `<prefix>:<identifier>`.
 *
 * One prefix per kind of state (`session`, `login-state`, `login-attempts`, …), so a
 * key says what it is and two stores can never collide.
 */
final class Keys
{
    private function __construct()
    {
    }

    /**
     * The key for state reached through a secret: a session cookie, a login-state
     * handle, a device code.
     *
     * The secret is digested first, so reading Redis — a dump, `MONITOR`, a log of
     * slow commands — never yields something a browser could present.
     */
    public static function forSecret(string $prefix, #[\SensitiveParameter] string $secret): string
    {
        return $prefix . ':' . Digest::of($secret)->toString();
    }

    /**
     * The key for state indexed by something that is not a secret: a user id, a `sid`.
     */
    public static function forIdentifier(string $prefix, string $identifier): string
    {
        return $prefix . ':' . $identifier;
    }
}
