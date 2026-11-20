<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Port;

use RuntimeException;

/**
 * The ciphertext, the key, or the context does not match.
 *
 * One error for a wrong key, a tampered ciphertext and a mismatched context alike: the
 * cipher cannot tell them apart, and neither should its callers.
 */
final class DecryptionFailed extends RuntimeException
{
}
