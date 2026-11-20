<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\LoginPage;

/**
 * The facts the login page is rendered from.
 */
final readonly class LoginPage
{
    /**
     * @param string|null  $signedInAs  The email of the person already signed in, when the page has no
     *                                  authorization request to return to; null shows the form.
     * @param list<string> $formOrigins Where a successful sign-in may end: the origins of the
     *                                  application's redirect URIs. Empty when no application is in play.
     */
    public function __construct(
        public ?string $signedInAs,
        public array $formOrigins,
    ) {
    }
}
