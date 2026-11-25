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
 * docs/design/saml-connections.md §3): generated here and sealed, or kept in a KMS that never lets
 * them out and named by the `CLAVIA_SAML_*_KEY_REF` settings. The same choice as
 * `CLAVIA_SIGNING_BACKEND`, made apart, because the keys and their usages differ.
 */
enum SamlKeyBackend: string
{
    /** Generated here, sealed with `CLAVIA_SECRET_ENCRYPTION_KEY`: extractable, as token keys in `postgres` are. */
    case Postgres = 'postgres';

    /** AWS KMS: a `SIGN_VERIFY` key and an `ENCRYPT_DECRYPT` key, named by ARN or id. */
    case AwsKms = 'aws-kms';

    /** Google Cloud KMS: an `ASYMMETRIC_SIGN` and an `ASYMMETRIC_DECRYPT` key version. */
    case GcpKms = 'gcp-kms';

    /** Azure Key Vault or Managed HSM: two RSA keys, by versioned URL. */
    case AzureKeyVault = 'azure-key-vault';

    /** Whether the keys are the provider's: rotation is the operator's there. */
    public function isRemote(): bool
    {
        return $this !== self::Postgres;
    }
}
