<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Connections;

use RuntimeException;
use Throwable;

/**
 * An identity provider's metadata that cannot be used, and the field it came in: `/saml/metadata`
 * or `/saml/metadata_url`, so the Management API's `422` points at it (§5.2). Never the content.
 */
final class SamlMetadataRefused extends RuntimeException
{
    public function __construct(public readonly string $pointer, string $reason, ?Throwable $previous = null)
    {
        parent::__construct($reason, 0, $previous);
    }
}
