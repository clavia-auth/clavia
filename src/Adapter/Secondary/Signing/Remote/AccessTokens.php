<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Signing\Remote;

use Clavia\Application\Port\SigningFailed;

/**
 * Bearer tokens for a signing service's API: Google's application default credentials,
 * an Azure managed identity or application. Each keeps the token it was issued until
 * shortly before it expires.
 */
interface AccessTokens
{
    /**
     * @return non-empty-string
     *
     * @throws SigningFailed When no token can be obtained.
     */
    public function token(): string;
}
