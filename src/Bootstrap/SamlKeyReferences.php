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
 * The SAML service provider's key references, held to their provider's form when the settings load
 * (docs/design/saml-connections.md §3): each names one immutable key version, never an alias that
 * could be repointed at another key. No provider is called, and `bin/clavia` stops (78) on a bad one.
 */
final class SamlKeyReferences
{
    private function __construct()
    {
    }

    /** @throws InvalidSettings */
    public static function check(Settings $settings): void
    {
        if (! $settings->samlKeyBackend->isRemote()) {
            return;
        }
        $references = [
            $settings->samlSigningKeyRef,
            $settings->samlEncryptionKeyRef,
            $settings->samlNextSigningKeyRef,
            $settings->samlNextEncryptionKeyRef,
            ...$settings->samlRetiredEncryptionKeyRefs,
        ];
        foreach ($references as $reference) {
            if ($reference !== null) {
                RemoteSigningKeys::check($settings->samlKeyBackend->value, $reference);
            }
        }
    }
}
