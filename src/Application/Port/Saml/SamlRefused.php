<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Port\Saml;

/** A response refused, with the category the log keeps (docs/design/saml-connections.md §5.3). */
final readonly class SamlRefused
{
    public function __construct(public SamlRefusal $reason)
    {
    }
}
