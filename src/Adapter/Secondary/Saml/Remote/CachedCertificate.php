<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Saml\Remote;

use Clavia\Domain\Connection\Saml\ServiceProviderKeyUsage;
use DateTimeImmutable;

/** A remote key's certificate, built once through the KMS, and its kid. */
final readonly class CachedCertificate
{
    /**
     * @param non-empty-string $kid
     * @param non-empty-string $certificate DER, base64.
     */
    public function __construct(
        public string $kid,
        public ServiceProviderKeyUsage $usage,
        public string $certificate,
        public DateTimeImmutable $validUntil,
        public DateTimeImmutable $createdAt,
    ) {
    }
}
