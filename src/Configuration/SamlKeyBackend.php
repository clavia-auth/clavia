<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Configuration;

/**
 * Where this server's SAML service provider keys live (`CLAVIA_SAML_KEY_BACKEND`,
 * docs/design/saml-connections.md §3). `postgres` only for now: the KMS backends (`aws-kms`,
 * `gcp-kms`, `azure-key-vault`) come with their key references in a later slice, and until then
 * naming one refuses to boot rather than running without keys.
 */
enum SamlKeyBackend: string
{
    /** Generated here, sealed with `CLAVIA_SECRET_ENCRYPTION_KEY`: extractable, as token keys in `postgres` are. */
    case Postgres = 'postgres';
}
