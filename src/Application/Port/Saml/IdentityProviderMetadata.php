<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Port\Saml;

use Clavia\Domain\Shared\Url;

/** What a connection needs from an identity provider's metadata (SAML Metadata §2.4.3). */
final readonly class IdentityProviderMetadata
{
    /**
     * @param non-empty-string                 $entityId
     * @param non-empty-list<non-empty-string> $certificates PEM, one to three, each an RSA key of 2048 bits or more.
     */
    public function __construct(
        public string $entityId,
        public Url $singleSignOnUrl,
        public array $certificates,
    ) {
    }
}
