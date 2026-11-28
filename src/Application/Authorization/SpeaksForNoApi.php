<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authorization;

use RuntimeException;

/**
 * The caller's client speaks for no API with fine-grained authorization switched on
 * (docs/design/fine-grained-authorization.md §5.2, step 2): there is no store it may ask or write.
 */
final class SpeaksForNoApi extends RuntimeException
{
    public function __construct()
    {
        parent::__construct('This client speaks for no API with fine-grained authorization on.');
    }
}
