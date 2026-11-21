<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap;

use Clavia\Configuration\InvalidSettings;
use Clavia\Configuration\Settings;

/**
 * The signing backends `CLAVIA_SIGNING_BACKEND` names.
 *
 * `postgres` keeps its keys in the database, sealed, and manages them itself (`clavia
 * keys:*`). Every other backend holds its keys at a provider that never lets them out —
 * created and rotated there, configured here by reference — and any value that is not a
 * built-in is the name of a class implementing
 * {@see \Clavia\Adapter\Secondary\Signing\Remote\RemoteSigningKey}.
 */
final class SigningBackend
{
    public const string POSTGRES = 'postgres';

    public const string AWS_KMS = 'aws-kms';

    public const string GCP_KMS = 'gcp-kms';

    public const string AZURE_KEY_VAULT = 'azure-key-vault';

    public const array BUILT_IN = [self::POSTGRES, self::AWS_KMS, self::GCP_KMS, self::AZURE_KEY_VAULT];

    private function __construct()
    {
    }

    /** Whether the configured backend keeps, and manages, its own keys. */
    public static function managesItsKeys(Settings $settings): bool
    {
        return $settings->signingBackend === self::POSTGRES;
    }

    /**
     * Refuse key management where the keys are the provider's: an operator who configured
     * a KMS must never end up with keys in PostgreSQL without knowing it.
     *
     * @throws InvalidSettings
     */
    public static function requireManagedKeys(Settings $settings): void
    {
        if (! self::managesItsKeys($settings)) {
            throw new InvalidSettings(sprintf(
                "CLAVIA_SIGNING_BACKEND='%s' keeps its keys at the provider: create and rotate them there, and "
                . 'name them with CLAVIA_SIGNING_KEY_REF and CLAVIA_SIGNING_RETIRED_KEY_REFS. Only the %s backend '
                . 'keeps keys this server manages.',
                $settings->signingBackend,
                self::POSTGRES,
            ));
        }
    }
}
