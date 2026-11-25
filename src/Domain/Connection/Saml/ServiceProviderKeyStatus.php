<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Connection\Saml;

/** A service provider key's place in the rotation (§5.1). */
enum ServiceProviderKeyStatus: string
{
    /** Published in the metadata beside the current one, not used yet: identity providers pick it up. */
    case Next = 'next';

    /** Signs requests, or receives assertions, now. */
    case Current = 'current';

    /** Replaced: no longer published. A retired encryption key still decrypts until it is deleted. */
    case Retired = 'retired';
}
