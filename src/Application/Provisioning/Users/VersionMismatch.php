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
 * A change conditioned on a version (`If-Match`) that is no longer the resource's: RFC 7644 §3.14's
 * `412 Precondition Failed`. A directory and an operator editing one account at once do not
 * overwrite each other silently.
 */
final readonly class VersionMismatch
{
}
