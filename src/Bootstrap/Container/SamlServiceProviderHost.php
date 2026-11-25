<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Configuration\Settings;
use LogicException;

/** The sign-in host, as the service provider's certificates name it (`CN=<host> SAML SP`). */
final class SamlServiceProviderHost
{
    private function __construct()
    {
    }

    /** @return non-empty-string */
    public static function of(Settings $settings): string
    {
        $host = parse_url($settings->issuerUrl, PHP_URL_HOST);

        return is_string($host) && $host !== '' ? $host : throw new LogicException('The issuer has no host.');
    }
}
