<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\SignIn;

use Clavia\Domain\Client\InitiateLoginUri;

/**
 * The sign-in names a held request (a login state's handle) that no longer exists: it expired,
 * was spent by another tab, or never was. Nobody is signed in and nothing is started, since a
 * sign-in without its request could only land on this server's own pages while the application
 * waits for an answer it will never get (#218).
 *
 * Only the application can start again. When the store still remembers which one the request was
 * for and it registered a sign-in start address, that address is here, and the person is sent there
 * (#219); otherwise they are told to go back to it.
 *
 * A sign-in that names no request at all (the login page opened directly) is not this.
 */
final readonly class SignInRequestExpired implements SignInOutcome
{
    /**
     * @param InitiateLoginUri|null $restartAt The application's `initiate_login_uri`, registered by an
     *                                         operator; never anything the request carried.
     */
    public function __construct(public ?InitiateLoginUri $restartAt = null)
    {
    }
}
