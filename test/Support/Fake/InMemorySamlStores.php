<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Application\Port\Saml\ParkedSamlResponse;
use Clavia\Application\Port\Saml\SamlAssertionReplayCache;
use Clavia\Application\Port\Saml\SamlResponseStore;
use Clavia\Domain\Connection\ConnectionName;

/** The ACS handles and the assertion replay cache, in memory. Time-to-live is not kept. */
final class InMemorySamlStores implements SamlResponseStore, SamlAssertionReplayCache
{
    /** @var array<string, ParkedSamlResponse> */
    private array $parked = [];

    /** @var array<string, true> */
    private array $claimed = [];

    #[\Override]
    public function park(#[\SensitiveParameter] string $handle, ParkedSamlResponse $response): void
    {
        $this->parked[$handle] = $response;
    }

    #[\Override]
    public function claim(#[\SensitiveParameter] string $handle): ?ParkedSamlResponse
    {
        $response = $this->parked[$handle] ?? null;
        unset($this->parked[$handle]);

        return $response;
    }

    #[\Override]
    public function claimAssertion(ConnectionName $connection, string $assertionId, int $ttlSeconds): bool
    {
        $key = $connection->value . "\0" . $assertionId;
        if (isset($this->claimed[$key])) {
            return false;
        }
        $this->claimed[$key] = true;

        return true;
    }
}
