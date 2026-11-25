<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Connection\Saml;

/**
 * What a service provider key is for: one key, one usage (docs/design/saml-connections.md §2, §7).
 * A KMS key has a single purpose, and one key for both is what the cryptographic guidance warns
 * against.
 */
enum ServiceProviderKeyUsage: string
{
    /** Signs `AuthnRequest`s, and both certificates of its pair. */
    case Signing = 'signing';

    /** Decrypts the content key of an assertion encrypted to it (RSA-OAEP); signs nothing. */
    case Encryption = 'encryption';
}
