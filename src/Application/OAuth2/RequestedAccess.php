<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\OAuth2;

use Clavia\Domain\ResourceServer\ResourceServer;
use Clavia\Domain\Shared\ScopeSet;

/**
 * What a request for a person's tokens asks for: a scope, and the API it is for, if any.
 */
final readonly class RequestedAccess
{
    public function __construct(
        public ScopeSet $scope,
        public ?ResourceServer $target,
    ) {
    }
}
