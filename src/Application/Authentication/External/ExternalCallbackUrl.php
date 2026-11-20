<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\External;

use Clavia\Domain\Identity\ProviderName;

/**
 * The redirect URI Clavia registers at an external provider — and sends, identically,
 * when it starts a sign-in and when it exchanges the code (RFC 6749 §4.1.3).
 */
final class ExternalCallbackUrl
{
    /** The route of the callback; the HTTP adapter serves exactly this. */
    public const string PATH = '/auth/social/%s/callback';

    private function __construct()
    {
    }

    public static function for(string $issuer, ProviderName $provider): string
    {
        return rtrim($issuer, '/') . sprintf(self::PATH, $provider->value);
    }
}
