<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Connections;

/** What an identity provider's administrator is given for a SAML connection, and what is missing. */
final readonly class DescribedServiceProvider
{
    /**
     * @param non-empty-string      $entityId
     * @param non-empty-string      $assertionConsumerServiceUrl
     * @param non-empty-string      $metadataUrl
     * @param non-empty-string|null $warning Why requests are unsigned and assertions cannot be encrypted.
     */
    public function __construct(
        public string $entityId,
        public string $assertionConsumerServiceUrl,
        public string $metadataUrl,
        public ?string $warning,
    ) {
    }
}
