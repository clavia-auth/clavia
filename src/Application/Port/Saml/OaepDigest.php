<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Port\Saml;

/**
 * The digest of RSA-OAEP key transport (RFC 8017 §7.1): SHA-1 for XML Encryption's `rsa-oaep-mgf1p`
 * (its only one), SHA-1 or SHA-256 for XML Encryption 1.1's `rsa-oaep`. MGF1 uses the same digest.
 * PKCS#1 v1.5 key transport is not a choice: it is open to Bleichenbacher's attack.
 */
enum OaepDigest: string
{
    case Sha1 = 'sha1';
    case Sha256 = 'sha256';
}
