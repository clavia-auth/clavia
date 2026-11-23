<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Persistence\PhpDb;

use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\Registration\ClientRegistration;
use Clavia\Domain\Client\Registration\ClientRegistrationRepository;
use Clavia\Domain\Client\Registration\InitialAccessTokenId;
use Clavia\Domain\Shared\Digest;

/**
 * Registrations in `client_registrations`, one row per self-registered client.
 *
 * @psalm-type RegistrationRow = array{client_id: string, access_token_hash: string,
 *                                     initial_access_token_id: string|null, registered_at: string}
 */
final readonly class PhpDbClientRegistrationRepository implements ClientRegistrationRepository
{
    public function __construct(private Database $database)
    {
    }

    #[\Override]
    public function add(ClientRegistration $registration): void
    {
        $this->database->execute(
            <<<'SQL'
                INSERT INTO client_registrations
                    (client_id, access_token_hash, initial_access_token_id, registered_at)
                VALUES (:client_id, :access_token_hash, :initial_access_token_id, :registered_at)
                SQL,
            [
                'client_id' => $registration->clientId->value,
                'access_token_hash' => $registration->accessTokenDigest->toString(),
                'initial_access_token_id' => $registration->initialAccessTokenId?->value,
                'registered_at' => Timestamp::toDatabase($registration->registeredAt),
            ],
        );
    }

    #[\Override]
    public function find(ClientId $clientId): ?ClientRegistration
    {
        /** @var RegistrationRow|null $row */
        $row = $this->database->fetchOne(
            'SELECT client_id, access_token_hash, initial_access_token_id, registered_at '
            . 'FROM client_registrations WHERE client_id = :client_id',
            ['client_id' => $clientId->value],
        );

        if ($row === null) {
            return null;
        }
        $initialAccessTokenId = $row['initial_access_token_id'];

        return new ClientRegistration(
            ClientId::fromString($row['client_id']),
            Digest::fromHex($row['access_token_hash']),
            $initialAccessTokenId === null ? null : InitialAccessTokenId::fromString($initialAccessTokenId),
            Timestamp::fromDatabase($row['registered_at']),
        );
    }
}
