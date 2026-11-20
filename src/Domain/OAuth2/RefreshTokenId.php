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
 * Identifies the record of a refresh token — not the token itself, which is a secret
 * and stored only as a digest. The id of a family's first token is the family's id.
 */
final readonly class RefreshTokenId extends UuidId
{
}
