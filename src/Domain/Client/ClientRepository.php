<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Client;

/**
 * Where registered client applications are kept.
 */
interface ClientRepository
{
    public function find(ClientId $id): ?Client;

    /**
     * Look a client up by its display name.
     *
     * Names are not unique in general; this exists for provisioning that must be
     * idempotent and has no fixed id to key on, since ids are generated. Returns the
     * oldest client carrying the name.
     */
    public function findByName(string $name): ?Client;

    /** Insert the client, or update it when it already exists. */
    public function save(Client $client): void;
}
