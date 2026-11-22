<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Persistence\PhpDb;

use Clavia\Domain\Authentication\Passkey\Aaguid;
use Clavia\Domain\Authentication\Passkey\CoseAlgorithm;
use Clavia\Domain\Authentication\Passkey\CosePublicKey;
use Clavia\Domain\Authentication\Passkey\CredentialId;
use Clavia\Domain\Authentication\Passkey\Passkey;
use Clavia\Domain\Authentication\Passkey\PasskeyId;
use Clavia\Domain\Authentication\Passkey\PasskeyName;
use Clavia\Domain\Authentication\Passkey\PasskeyRepository;
use Clavia\Domain\Authentication\Passkey\Transport;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Shared\AlreadyExists;
use Throwable;

/**
 * Passkeys in `passkeys`.
 *
 * The credential id and the public key are `bytea`, passed and read as hexadecimal
 * (`decode(…, 'hex')`, `encode(…, 'hex')`): an arbitrary byte string is not text, and the driver
 * must not be asked to treat it as such. The unique constraint on the credential id decides
 * whether a credential is already registered; a counter moves only through the conditional
 * write of {@see self::recordUse()}.
 *
 * @psalm-type PasskeyRow = array{id: string, user_id: string, credential_id: string, public_key: string,
 *     algorithm: int|string, sign_count: int|string, transports: string, aaguid: string|null,
 *     backup_eligible: bool, backed_up: bool, name: string, created_at: string, last_used_at: string|null}
 */
final readonly class PhpDbPasskeyRepository implements PasskeyRepository
{
    private const string UNIQUE_CREDENTIAL_ID = 'uq_passkeys_credential_id';

    private const string COLUMNS = <<<'SQL'
        id, user_id, encode(credential_id, 'hex') AS credential_id, encode(public_key, 'hex') AS public_key,
        algorithm, sign_count, transports, aaguid, backup_eligible, backed_up, name, created_at, last_used_at
        SQL;

    public function __construct(private Database $database)
    {
    }

    #[\Override]
    public function save(Passkey $passkey): void
    {
        try {
            $this->database->execute(
                <<<'SQL'
                    INSERT INTO passkeys (
                        id, user_id, credential_id, public_key, algorithm, sign_count, transports, aaguid,
                        backup_eligible, backed_up, name, created_at, last_used_at
                    ) VALUES (
                        :id, :user_id, decode(:credential_id, 'hex'), decode(:public_key, 'hex'), :algorithm,
                        :sign_count, CAST(:transports AS jsonb), :aaguid, :backup_eligible, :backed_up, :name,
                        :created_at, :last_used_at
                    )
                    ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name
                    SQL,
                [
                    'id' => $passkey->id->value,
                    'user_id' => $passkey->userId->value,
                    'credential_id' => bin2hex($passkey->credentialId->bytes()),
                    'public_key' => bin2hex($passkey->publicKey->bytes()),
                    'algorithm' => $passkey->algorithm->value,
                    'sign_count' => $passkey->signCount,
                    'transports' => Jsonb::encode(array_map(
                        static fn (Transport $transport): string => $transport->value,
                        $passkey->transports,
                    )),
                    'aaguid' => $passkey->aaguid?->value,
                    'backup_eligible' => $passkey->backupEligible,
                    'backed_up' => $passkey->backedUp,
                    'name' => $passkey->name->value,
                    'created_at' => Timestamp::toDatabase($passkey->createdAt),
                    'last_used_at' => Timestamp::toDatabaseOrNull($passkey->lastUsedAt),
                ],
            );
        } catch (Throwable $failure) {
            if (Constraint::isUniqueViolation($failure, self::UNIQUE_CREDENTIAL_ID)) {
                throw new AlreadyExists('This credential is already registered.', 0, $failure);
            }

            throw $failure;
        }
    }

    #[\Override]
    public function recordUse(Passkey $passkey, int $previousSignCount): bool
    {
        return $this->database->execute(
            <<<'SQL'
                UPDATE passkeys
                SET sign_count = :sign_count, backed_up = :backed_up, last_used_at = :last_used_at
                WHERE id = :id AND sign_count = :previous_sign_count
                SQL,
            [
                'id' => $passkey->id->value,
                'sign_count' => $passkey->signCount,
                'backed_up' => $passkey->backedUp,
                'last_used_at' => Timestamp::toDatabaseOrNull($passkey->lastUsedAt),
                'previous_sign_count' => $previousSignCount,
            ],
        ) === 1;
    }

    #[\Override]
    public function ofCredentialId(CredentialId $credentialId): ?Passkey
    {
        /** @var PasskeyRow|null $row */
        $row = $this->database->fetchOne(
            'SELECT ' . self::COLUMNS . " FROM passkeys WHERE credential_id = decode(:credential_id, 'hex')",
            ['credential_id' => bin2hex($credentialId->bytes())],
        );

        return $row === null ? null : self::hydrate($row);
    }

    #[\Override]
    public function ofUser(UserId $userId): array
    {
        /** @var list<PasskeyRow> $rows */
        $rows = $this->database->fetchAll(
            'SELECT ' . self::COLUMNS . ' FROM passkeys WHERE user_id = :user_id ORDER BY created_at, id',
            ['user_id' => $userId->value],
        );

        return array_map(self::hydrate(...), $rows);
    }

    #[\Override]
    public function one(PasskeyId $id): ?Passkey
    {
        /** @var PasskeyRow|null $row */
        $row = $this->database->fetchOne(
            'SELECT ' . self::COLUMNS . ' FROM passkeys WHERE id = :id',
            ['id' => $id->value],
        );

        return $row === null ? null : self::hydrate($row);
    }

    #[\Override]
    public function delete(PasskeyId $id): void
    {
        $this->database->execute('DELETE FROM passkeys WHERE id = :id', ['id' => $id->value]);
    }

    #[\Override]
    public function countOf(UserId $userId): int
    {
        /** @var int|string $count */
        $count = $this->database->fetchValue(
            'SELECT count(*) FROM passkeys WHERE user_id = :user_id',
            ['user_id' => $userId->value],
        );

        return max(0, (int) $count);
    }

    #[\Override]
    public function countsAmong(array $userIds): array
    {
        if ($userIds === []) {
            return [];
        }
        $parameters = [];
        foreach ($userIds as $index => $userId) {
            $parameters['user_' . $index] = $userId->value;
        }
        /** @var list<array{user_id: string, passkeys: int|string}> $rows */
        $rows = $this->database->fetchAll(
            'SELECT user_id, count(*) AS passkeys FROM passkeys WHERE user_id IN ('
            . implode(', ', array_map(static fn (string $name): string => ':' . $name, array_keys($parameters)))
            . ') GROUP BY user_id',
            $parameters,
        );

        $counts = [];
        foreach ($rows as $row) {
            $count = (int) $row['passkeys'];
            assert($count > 0);
            $counts[$row['user_id']] = $count;
        }

        return $counts;
    }

    /**
     * @param PasskeyRow $row
     */
    private static function hydrate(array $row): Passkey
    {
        return Passkey::reconstitute(
            PasskeyId::fromString($row['id']),
            UserId::fromString($row['user_id']),
            CredentialId::fromBytes(self::bytes($row['credential_id'])),
            CosePublicKey::fromBytes(self::bytes($row['public_key'])),
            CoseAlgorithm::fromIdentifier((int) $row['algorithm']),
            (int) $row['sign_count'],
            array_map(Transport::from(...), Jsonb::decodeStrings($row['transports'])),
            $row['aaguid'] === null ? null : Aaguid::fromString($row['aaguid']),
            $row['backup_eligible'],
            $row['backed_up'],
            PasskeyName::fromString($row['name']),
            Timestamp::fromDatabase($row['created_at']),
            Timestamp::fromDatabaseOrNull($row['last_used_at']),
        );
    }

    private static function bytes(string $hex): string
    {
        $bytes = hex2bin($hex);
        if ($bytes === false) {
            throw new \UnexpectedValueException('PostgreSQL returned a byte string that is not hexadecimal.');
        }

        return $bytes;
    }
}
