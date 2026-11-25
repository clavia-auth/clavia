<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Adapter\Secondary\Saml\Remote\CachedCertificate;
use Clavia\Adapter\Secondary\Saml\Remote\CertificateCache;

/** Remote SAML key certificates in memory; the first put wins, as in the database. */
final class InMemoryCertificateCache implements CertificateCache
{
    /** @var array<string, CachedCertificate> */
    public array $certificates = [];

    #[\Override]
    public function get(string $reference): ?CachedCertificate
    {
        return $this->certificates[$reference] ?? null;
    }

    #[\Override]
    public function put(string $reference, CachedCertificate $certificate): void
    {
        $this->certificates[$reference] ??= $certificate;
    }
}
