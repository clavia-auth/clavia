<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Authentication\Passkey;

use Clavia\Domain\Shared\UuidId;

/**
 * Identifies a passkey in Clavia: in URLs and in the Management API.
 *
 * Not the WebAuthn credential id, which is the authenticator's and is never shown: this is
 * the handle a person or an operator uses to rename or remove one.
 */
final readonly class PasskeyId extends UuidId
{
}
