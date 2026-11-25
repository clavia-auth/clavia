<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Connections;

use Clavia\Domain\Connection\Saml\SamlOptions;

/** The `saml` of a new connection: its identity provider's metadata, given whole or by URL, and the options. */
final readonly class NewSamlConnection
{
    public function __construct(
        public ?string $metadata,
        public ?string $metadataUrl,
        public SamlOptions $options,
    ) {
    }
}
