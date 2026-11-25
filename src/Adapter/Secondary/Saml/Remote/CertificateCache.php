<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Saml\Remote;

/**
 * The certificates of remote service provider keys, by reference: a certificate needs a signature
 * from the KMS, so it is built once and kept, and the metadata never calls the KMS
 * (docs/design/saml-connections.md §5.1). Safe because a reference names one immutable key version.
 */
interface CertificateCache
{
    public function get(string $reference): ?CachedCertificate;

    public function put(string $reference, CachedCertificate $certificate): void;
}
