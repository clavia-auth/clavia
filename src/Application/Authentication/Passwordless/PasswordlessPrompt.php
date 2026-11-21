<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\Passwordless;

/**
 * What the page answering a pending sign-in shows: the address the proof went to, and
 * where its form may lead — the origins of the application the sign-in is for, which a
 * successful submission redirects on to.
 */
final readonly class PasswordlessPrompt
{
    /**
     * @param non-empty-string $email
     * @param list<string>     $formOrigins
     */
    public function __construct(
        public string $email,
        public array $formOrigins,
    ) {
    }
}
