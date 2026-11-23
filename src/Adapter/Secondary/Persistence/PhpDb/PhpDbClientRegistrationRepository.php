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
use DateTimeImmutable;

/**
 * Registrations in `client_registrations`, one row per self-registered client.
 *
 * @psalm-type RegistrationRow = array{client_id: string, access_token_hash: string,
 *                                     initial_access_token_id: string|null, registered_at: string,
 *                                     first_used_at: string|null}
 */
final readonly class PhpDbClientRegistrationRepository implements ClientRegistrationRepository
{
    private const string COLUMNS =
        'client_id, access_token_hash, initial_access_token_id, registered_at, first_used_at';

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
            'SELECT ' . self::COLUMNS . ' FROM client_registrations WHERE client_id = :client_id',
            ['client_id' => $clientId->value],
        );

        return $row === null ? null : self::hydrate($row);
    }

    #[\Override]
    public function findByAccessToken(Digest $digest): ?ClientRegistration
    {
        /** @var RegistrationRow|null $row */
        $row = $this->database->fetchOne(
            'SELECT ' . self::COLUMNS . ' FROM client_registrations WHERE access_token_hash = :hash',
            ['hash' => $digest->toString()],
        );

        return $row === null ? null : self::hydrate($row);
    }

    #[\Override]
    public function ofClients(array $clientIds): array
    {
        if ($clientIds === []) {
            return [];
        }
        /** @var list<RegistrationRow> $rows */
        $rows = $this->database->fetchAll(
            'SELECT ' . self::COLUMNS . ' FROM client_registrations '
            . 'WHERE client_id IN (SELECT jsonb_array_elements_text(CAST(:client_ids AS jsonb)))',
            ['client_ids' => Jsonb::encode(array_map(static fn (ClientId $id): string => $id->value, $clientIds))],
        );

        return array_map(self::hydrate(...), $rows);
    }

    #[\Override]
    public function save(ClientRegistration $registration): void
    {
        $this->database->execute(
            'UPDATE client_registrations SET access_token_hash = :hash WHERE client_id = :client_id',
            ['hash' => $registration->accessTokenDigest->toString(), 'client_id' => $registration->clientId->value],
        );
    }

    #[\Override]
    public function markUsed(ClientId $clientId, DateTimeImmutable $at): void
    {
        $this->database->execute(
            'UPDATE client_registrations SET first_used_at = :at '
            . 'WHERE client_id = :client_id AND first_used_at IS NULL',
            ['at' => Timestamp::toDatabase($at), 'client_id' => $clientId->value],
        );
    }

    #[\Override]
    public function neverUsedSince(DateTimeImmutable $before): array
    {
        /** @var list<string> $ids */
        $ids = array_column($this->database->fetchAll(
            'SELECT client_id FROM client_registrations WHERE first_used_at IS NULL AND registered_at < :before '
            . 'ORDER BY registered_at, client_id',
            ['before' => Timestamp::toDatabase($before)],
        ), 'client_id');

        return array_map(ClientId::fromString(...), $ids);
    }

    /** @param RegistrationRow $row */
    private static function hydrate(array $row): ClientRegistration
    {
        $initialAccessTokenId = $row['initial_access_token_id'];

        return new ClientRegistration(
            ClientId::fromString($row['client_id']),
            Digest::fromHex($row['access_token_hash']),
            $initialAccessTokenId === null ? null : InitialAccessTokenId::fromString($initialAccessTokenId),
            Timestamp::fromDatabase($row['registered_at']),
            $row['first_used_at'] === null ? null : Timestamp::fromDatabase($row['first_used_at']),
        );
    }
}
