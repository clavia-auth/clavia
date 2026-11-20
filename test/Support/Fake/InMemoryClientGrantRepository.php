<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Domain\Client\ClientId;
use Clavia\Domain\ResourceServer\ClientGrant;
use Clavia\Domain\ResourceServer\ClientGrantRepository;
use Clavia\Domain\ResourceServer\ResourceServerId;

final class InMemoryClientGrantRepository implements ClientGrantRepository
{
    /** @var array<string, ClientGrant> */
    private array $grants = [];

    #[\Override]
    public function find(ClientId $client, ResourceServerId $resourceServer): ?ClientGrant
    {
        return $this->grants[$client->value . '|' . $resourceServer->value] ?? null;
    }

    #[\Override]
    public function save(ClientGrant $grant): void
    {
        $key = $grant->clientId->value . '|' . $grant->resourceServerId->value;
        $existing = $this->grants[$key] ?? null;

        // The first grant's creation date is kept, as the table's upsert keeps it.
        $this->grants[$key] = $existing === null ? $grant : ClientGrant::reconstitute(
            $grant->clientId,
            $grant->resourceServerId,
            $grant->scopes,
            $existing->createdAt,
        );
    }

    /** Drop every grant on an API that was deleted. */
    public function forgetApi(ResourceServerId $resourceServer): void
    {
        $this->grants = array_filter(
            $this->grants,
            static fn (ClientGrant $grant): bool => ! $grant->resourceServerId->equals($resourceServer),
        );
    }
}
