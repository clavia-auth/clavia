<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Persistence\PhpDb;

use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Provisioning\ProvisioningToken;
use Clavia\Domain\Provisioning\ProvisioningTokenId;
use Clavia\Domain\Provisioning\ProvisioningTokenRepository;
use Clavia\Domain\Provisioning\SubjectAttribute;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\Page;
use Clavia\Domain\Shared\PageRequest;

/**
 * Provisioning tokens in `provisioning_tokens`, by the digest of the secret. A token goes with its
 * connection (`ON DELETE CASCADE`).
 *
 * @psalm-type TokenRow = array{id: string, token_hash: string, connection: string, description: string,
 *                              created_at: string, expires_at: string, revoked_at: string|null,
 *                              subject_attribute: string, addresses_trusted: bool, delete_deactivates: bool}
 */
final readonly class PhpDbProvisioningTokenRepository implements ProvisioningTokenRepository
{
    private const string COLUMNS = 'id, token_hash, connection, description, created_at, expires_at, revoked_at, '
        . 'subject_attribute, addresses_trusted, delete_deactivates';

    public function __construct(private Database $database)
    {
    }

    #[\Override]
    public function add(ProvisioningToken $token): void
    {
        $this->database->execute(
            <<<'SQL'
                INSERT INTO provisioning_tokens (
                    id, token_hash, connection, description, created_at, expires_at, revoked_at,
                    subject_attribute, addresses_trusted, delete_deactivates
                ) VALUES (
                    :id, :token_hash, :connection, :description, :created_at, :expires_at, :revoked_at,
                    :subject_attribute, :addresses_trusted, :delete_deactivates
                )
                SQL,
            [
                'id' => $token->id->value,
                'token_hash' => $token->digest->toString(),
                'connection' => $token->connection->value,
                'description' => $token->description,
                'created_at' => Timestamp::toDatabase($token->createdAt),
                'expires_at' => Timestamp::toDatabase($token->expiresAt),
                'revoked_at' => $token->revokedAt === null ? null : Timestamp::toDatabase($token->revokedAt),
                'subject_attribute' => $token->subjectAttribute->value,
                'addresses_trusted' => $token->addressesTrusted,
                'delete_deactivates' => $token->deleteDeactivates,
            ],
        );
    }

    #[\Override]
    public function find(ProvisioningTokenId $id): ?ProvisioningToken
    {
        /** @var TokenRow|null $row */
        $row = $this->database->fetchOne(
            'SELECT ' . self::COLUMNS . ' FROM provisioning_tokens WHERE id = :id',
            ['id' => $id->value],
        );

        return $row === null ? null : self::hydrate($row);
    }

    #[\Override]
    public function findByDigest(Digest $digest): ?ProvisioningToken
    {
        /** @var TokenRow|null $row */
        $row = $this->database->fetchOne(
            'SELECT ' . self::COLUMNS . ' FROM provisioning_tokens WHERE token_hash = :token_hash',
            ['token_hash' => $digest->toString()],
        );

        return $row === null ? null : self::hydrate($row);
    }

    #[\Override]
    public function save(ProvisioningToken $token): void
    {
        $this->database->execute(
            'UPDATE provisioning_tokens SET revoked_at = :revoked_at WHERE id = :id',
            [
                'id' => $token->id->value,
                'revoked_at' => $token->revokedAt === null ? null : Timestamp::toDatabase($token->revokedAt),
            ],
        );
    }

    #[\Override]
    public function page(PageRequest $request, ?ConnectionName $connection = null): Page
    {
        $search = Search::across($request, ['description']);
        $where = $search->where;
        $parameters = $search->parameters;
        if ($connection !== null) {
            $where = $where === ''
                ? 'WHERE connection = :connection'
                : 'WHERE (' . substr($where, strlen('WHERE ')) . ') AND connection = :connection';
            $parameters['connection'] = $connection->value;
        }
        /** @var int|string $total */
        $total = $this->database->fetchValue('SELECT count(*) FROM provisioning_tokens ' . $where, $parameters);
        /** @var list<TokenRow> $rows */
        $rows = $this->database->fetchAll(
            'SELECT ' . self::COLUMNS . ' FROM provisioning_tokens ' . $where
            . ' ORDER BY created_at DESC, id LIMIT :limit OFFSET :offset',
            $parameters + $search->pageParameters($request),
        );

        return new Page(array_map(self::hydrate(...), $rows), max(0, (int) $total), $request);
    }

    /** @param TokenRow $row */
    private static function hydrate(array $row): ProvisioningToken
    {
        return ProvisioningToken::reconstitute(
            ProvisioningTokenId::fromString($row['id']),
            Digest::fromHex($row['token_hash']),
            ConnectionName::fromString($row['connection']),
            $row['description'],
            Timestamp::fromDatabase($row['created_at']),
            Timestamp::fromDatabase($row['expires_at']),
            $row['revoked_at'] === null ? null : Timestamp::fromDatabase($row['revoked_at']),
            SubjectAttribute::from($row['subject_attribute']),
            $row['addresses_trusted'],
            $row['delete_deactivates'],
        );
    }
}
