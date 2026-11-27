<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\SignIn;

use Clavia\Application\Port\LoginStateStore;
use Clavia\Domain\Authentication\LoginState;

/**
 * The request a sign-in page was opened for, as every first factor reads it: the one place that
 * tells "no request" from "a request that is gone".
 *
 * - no handle (null or empty): the page was opened directly; the sign-in ends on this server's
 *   own pages, as it always has;
 * - a handle naming a login state: the request, to resume once the person is in;
 * - a handle naming nothing: {@see SignInRequestExpired}, a refusal. Signing in regardless would
 *   strand the person on "you are signed in" while the application never hears back, and would
 *   ignore which connections that application allows.
 */
final class HeldSignInRequest
{
    private function __construct()
    {
    }

    /** @return LoginState|SignInRequestExpired|null Null when no handle was given. */
    public static function find(
        LoginStateStore $loginStates,
        #[\SensitiveParameter] ?string $handle,
    ): LoginState|SignInRequestExpired|null {
        if ($handle === null || $handle === '') {
            return null;
        }

        return $loginStates->get($handle) ?? new SignInRequestExpired();
    }

    /** Whether a handle was given and names nothing: for the pages, before they offer a form. */
    public static function hasExpired(LoginStateStore $loginStates, #[\SensitiveParameter] ?string $handle): bool
    {
        return self::find($loginStates, $handle) instanceof SignInRequestExpired;
    }
}
