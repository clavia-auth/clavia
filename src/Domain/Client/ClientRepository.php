<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Client;

use Clavia\Domain\Shared\Page;
use Clavia\Domain\Shared\PageRequest;

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

    /**
     * Whether any client registers a redirect URI on this origin (`scheme://host[:port]`,
     * as {@see \Clavia\Domain\Shared\Url::origin()} spells it).
     *
     * The trust anchor for a redirect that legitimately leaves this server — after
     * logout, to the application the person came from: the same registrations the
     * authorization endpoint trusts, rather than a second allowlist that could drift.
     */
    public function registersRedirectOrigin(string $origin): bool;

    /** Insert the client, or update it when it already exists. */
    public function save(Client $client): void;

    /**
     * Remove the client, and with it every code, token and grant it holds.
     */
    public function delete(ClientId $id): void;

    /**
     * Clients newest first, searching the id and the name: an operator arrives with
     * whichever one they were given.
     *
     * @return Page<Client>
     */
    public function page(PageRequest $request): Page;
}
