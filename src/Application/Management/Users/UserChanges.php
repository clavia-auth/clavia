<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Users;

use Clavia\Domain\Identity\AppMetadata;

/**
 * Changes to an account. A field left null is left alone; a profile field present in
 * `$profile` with a null value is cleared.
 */
final readonly class UserChanges
{
    /**
     * @param array<'name'|'given_name'|'family_name'|'nickname'|'picture'|'locale', string|null> $profile
     */
    public function __construct(
        public ?string $email = null,
        #[\SensitiveParameter] public ?string $password = null,
        public ?bool $emailVerified = null,
        public ?bool $isActive = null,
        public array $profile = [],
        public ?AppMetadata $appMetadata = null,
    ) {
    }
}
