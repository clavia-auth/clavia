<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Connection\Saml;

use Clavia\Application\Port\Saml\ServiceProviderKeys;
use Clavia\Domain\Connection\Saml\ServiceProviderKeySet;

/** `clavia saml-keys:list` and `GET /api/v1/saml-keys`: every key, by its certificate, never its material. */
final readonly class ListServiceProviderKeys
{
    public function __construct(private ServiceProviderKeys $keys)
    {
    }

    public function __invoke(): ServiceProviderKeySet
    {
        return $this->keys->certificates();
    }
}
