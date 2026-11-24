<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Users\Jobs;

/**
 * One account an import line describes, read and checked ({@see ImportLine}).
 */
final readonly class ImportedAccount
{
    /**
     * @param array<'name'|'given_name'|'family_name'|'nickname'|'picture'|'locale', string> $profile
     * @param non-empty-string|null $passwordHash A hash this server can verify; null for no password.
     */
    public function __construct(
        public string $email,
        #[\SensitiveParameter] public ?string $passwordHash,
        public bool $emailVerified,
        public bool $isActive,
        public array $profile,
    ) {
    }
}
