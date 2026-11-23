<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Client\Registration;

use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Shared\Digest;
use DateTimeImmutable;

/**
 * The registrations of clients that registered themselves. Deleting a client deletes its
 * registration (a foreign key that cascades).
 */
interface ClientRegistrationRepository
{
    public function add(ClientRegistration $registration): void;

    public function find(ClientId $clientId): ?ClientRegistration;

    /** The registration a registration access token answers for, by the token's digest. */
    public function findByAccessToken(Digest $digest): ?ClientRegistration;

    /**
     * The registrations of these clients, those that have one: a page of clients is described in
     * one query.
     *
     * @param list<ClientId> $clientIds
     *
     * @return list<ClientRegistration>
     */
    public function ofClients(array $clientIds): array;

    /** Record a new registration access token. */
    public function save(ClientRegistration $registration): void;

    /**
     * Record the client's first token, at `$at`: one conditional write, a no-op for an operator's
     * client (no registration) and for every token after the first.
     */
    public function markUsed(ClientId $clientId, DateTimeImmutable $at): void;

    /**
     * The self-registered clients never issued a token and registered before `$before`, oldest
     * first.
     *
     * @return list<ClientId>
     */
    public function neverUsedSince(DateTimeImmutable $before): array;
}
