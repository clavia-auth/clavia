<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Connections;

/**
 * A connection to create: a pool, or an OpenID Connect provider.
 */
final readonly class NewConnection
{
    /**
     * @param string      $strategy         `database` or `oidc`; `social` is refused, the code's own.
     * @param string|null $oidcClientSecret Stored encrypted, never read back.
     * @param string|null $oidcScope        Defaults to `openid profile email`.
     */
    public function __construct(
        public string $name,
        public string $displayName,
        public string $strategy,
        public bool $isEnabled = true,
        public bool $isDomainConnection = false,
        public ?string $oidcIssuer = null,
        public ?string $oidcClientId = null,
        #[\SensitiveParameter] public ?string $oidcClientSecret = null,
        public ?string $oidcScope = null,
    ) {
    }

    public function hasOidcSettings(): bool
    {
        return $this->oidcIssuer !== null
            || $this->oidcClientId !== null
            || $this->oidcClientSecret !== null
            || $this->oidcScope !== null;
    }
}
