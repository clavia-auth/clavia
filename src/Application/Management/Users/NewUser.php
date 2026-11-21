<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Users;

/**
 * A new account: an address, a password, and optionally its standing and profile.
 */
final readonly class NewUser
{
    /**
     * @param array<'name'|'given_name'|'family_name'|'nickname'|'picture'|'locale', string> $profile
     * @param string|null $connection The pool it is created in; null for the default one.
     */
    public function __construct(
        public string $email,
        #[\SensitiveParameter] public string $password,
        public bool $emailVerified = false,
        public bool $isActive = true,
        public array $profile = [],
        public ?string $connection = null,
    ) {
    }
}
