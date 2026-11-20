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
 * Which signing backend the settings select, for the factories that build one.
 *
 * Only `postgres` is implemented. The remote backends the settings already describe
 * (`aws-kms`, `gcp-kms`, `azure-key-vault`, a custom class) are refused by name rather
 * than quietly replaced by the database backend: an operator who configured a KMS must
 * never end up with keys in PostgreSQL without knowing it.
 */
final class SigningBackend
{
    public const string POSTGRES = 'postgres';

    private function __construct()
    {
    }

    /**
     * @throws InvalidSettings
     */
    public static function requirePostgres(Settings $settings): void
    {
        if ($settings->signingBackend !== self::POSTGRES) {
            throw new InvalidSettings(sprintf(
                "CLAVIA_SIGNING_BACKEND='%s' is not available in this version of Clavia; use '%s'.",
                $settings->signingBackend,
                self::POSTGRES,
            ));
        }
    }
}
