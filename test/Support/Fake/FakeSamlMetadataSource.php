<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Application\Port\Saml\MetadataUnavailable;
use Clavia\Application\Port\Saml\SamlMetadataSource;
use Clavia\Domain\Shared\Url;

/** Metadata documents by URL, as a test sets them; any other URL is unavailable. */
final class FakeSamlMetadataSource implements SamlMetadataSource
{
    /** @var array<string, string> */
    public array $documents = [];

    /** @var list<string> */
    public array $fetched = [];

    #[\Override]
    public function fetch(Url $url): string
    {
        $this->fetched[] = $url->value;

        return $this->documents[$url->value] ?? throw new MetadataUnavailable('The metadata URL could not be reached.');
    }
}
