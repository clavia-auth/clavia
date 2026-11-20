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
 * Identifies the record of an access token — not the token itself, which is a secret
 * and stored only as a digest.
 */
final readonly class AccessTokenId extends UuidId
{
}
