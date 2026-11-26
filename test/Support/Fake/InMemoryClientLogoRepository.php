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
use Clavia\Domain\Client\ClientLogo;
use Clavia\Domain\Client\ClientLogoRepository;

final class InMemoryClientLogoRepository implements ClientLogoRepository
{
    /** @var array<string, ClientLogo> */
    private array $logos = [];

    #[\Override]
    public function save(ClientLogo $logo): void
    {
        $this->logos[$logo->clientId->value] = $logo;
    }

    #[\Override]
    public function find(ClientId $clientId): ?ClientLogo
    {
        return $this->logos[$clientId->value] ?? null;
    }

    #[\Override]
    public function versionOf(ClientId $clientId): ?string
    {
        return $this->find($clientId)?->version;
    }

    #[\Override]
    public function versionsOf(array $clientIds): array
    {
        $versions = [];
        foreach ($clientIds as $id) {
            $logo = $this->logos[$id->value] ?? null;
            if ($logo !== null) {
                $versions[$id->value] = $logo->version;
            }
        }

        return $versions;
    }

    #[\Override]
    public function delete(ClientId $clientId): bool
    {
        $had = isset($this->logos[$clientId->value]);
        unset($this->logos[$clientId->value]);

        return $had;
    }
}
