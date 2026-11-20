<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\OAuth2;

use Clavia\Domain\Shared\UuidId;

/**
 * Identifies the record of an authorization code — not the code itself, which is a
 * secret and stored only as a digest. Tokens point at this, so a replayed code can
 * revoke everything it produced.
 */
final readonly class AuthorizationCodeId extends UuidId
{
}
