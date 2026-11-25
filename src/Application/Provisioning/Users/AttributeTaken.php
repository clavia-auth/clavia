<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Provisioning\Users;

/**
 * A resource the connection cannot take because one of its unique attributes is someone else's:
 * RFC 7644 §3.3's `409 Conflict`, `scimType` `uniqueness`. It names the attribute, never the value.
 */
final readonly class AttributeTaken
{
    /** @param 'userName'|'externalId'|'emails'|'displayName' $attribute */
    public function __construct(public string $attribute)
    {
    }
}
