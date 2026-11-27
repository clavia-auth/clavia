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
use Clavia\Domain\Client\ClientRepository;

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

    /**
     * @return LoginState|SignInRequestExpired|null Null when no handle was given. A request that is gone
     *         names where its application starts a sign-in, when the store still remembers which one it
     *         was for and that application registered such an address (#219).
     */
    public static function find(
        LoginStateStore $loginStates,
        ClientRepository $clients,
        #[\SensitiveParameter] ?string $handle,
    ): LoginState|SignInRequestExpired|null {
        if ($handle === null || $handle === '') {
            return null;
        }

        $held = $loginStates->get($handle);
        if ($held !== null) {
            return $held;
        }
        $clientId = $loginStates->applicationOf($handle);

        return new SignInRequestExpired($clientId === null ? null : $clients->find($clientId)?->initiateLoginUri);
    }

    /**
     * What a page for `$handle` shows instead of a form: null while the request is there, or when the
     * page names none.
     */
    public static function expired(
        LoginStateStore $loginStates,
        ClientRepository $clients,
        #[\SensitiveParameter] ?string $handle,
    ): ?SignInRequestExpired {
        $found = self::find($loginStates, $clients, $handle);

        return $found instanceof SignInRequestExpired ? $found : null;
    }
}
