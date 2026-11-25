<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Port\Saml;

use Clavia\Domain\Shared\Url;

/**
 * Where an identity provider's metadata is read from when the operator gives its URL: fetched at
 * registration and on refresh only, never in a sign-in's path (docs/design/saml-connections.md §2,
 * "Metadata in"), held to `OutboundUrlPolicy` (no SSRF), bounded in size.
 */
interface SamlMetadataSource
{
    /** @throws MetadataUnavailable Refused, unreachable, not a 200, or too large; the reason is the operator's. */
    public function fetch(Url $url): string;
}
