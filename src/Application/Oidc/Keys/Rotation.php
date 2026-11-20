<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Oidc\Keys;

use Clavia\Domain\Oidc\SigningKey;

/**
 * The outcome of a key rotation.
 */
final readonly class Rotation
{
    /**
     * @param SigningKey      $active  The key that signs from now on.
     * @param SigningKey|null $retired The key it replaced, still published for the grace period;
     *                                 null when there was no active key to replace.
     */
    public function __construct(
        public SigningKey $active,
        public ?SigningKey $retired,
    ) {
    }
}
