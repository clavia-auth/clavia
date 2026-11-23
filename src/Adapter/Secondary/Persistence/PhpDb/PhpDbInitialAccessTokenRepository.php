<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Persistence\PhpDb;

use Clavia\Domain\Client\Registration\InitialAccessToken;
use Clavia\Domain\Client\Registration\InitialAccessTokenId;
use Clavia\Domain\Client\Registration\InitialAccessTokenRepository;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\Page;
use Clavia\Domain\Shared\PageRequest;
use DateTimeImmutable;

/**
 * Initial access tokens in `initial_access_tokens`, by the digest of the secret.
 *
 * A use is spent by one conditional `UPDATE … RETURNING`, whose `WHERE` is the whole rule: under
 * READ COMMITTED, two registrations racing for the last use see the row's latest version, and only
 * one of them matches.
 *
 * @psalm-type TokenRow = array{id: string, token_hash: string, description: string, created_at: string,
 *                              expires_at: string, max_uses: int, uses: int, revoked_at: string|null}
 */
final readonly class PhpDbInitialAccessTokenRepository implements InitialAccessTokenRepository
{
    private const string COLUMNS = 'id, token_hash, description, created_at, expires_at, max_uses, uses, revoked_at';

    public function __construct(private Database $database)
    {
    }

    #[\Override]
    public function add(InitialAccessToken $token): void
    {
        $this->database->execute(
            <<<'SQL'
                INSERT INTO initial_access_tokens
                    (id, token_hash, description, created_at, expires_at, max_uses, uses, revoked_at)
                VALUES (:id, :token_hash, :description, :created_at, :expires_at, :max_uses, :uses, :revoked_at)
                SQL,
            [
                'id' => $token->id->value,
                'token_hash' => $token->digest->toString(),
                'description' => $token->description,
                'created_at' => Timestamp::toDatabase($token->createdAt),
                'expires_at' => Timestamp::toDatabase($token->expiresAt),
                'max_uses' => $token->maxUses,
                'uses' => $token->uses,
                'revoked_at' => $token->revokedAt === null ? null : Timestamp::toDatabase($token->revokedAt),
            ],
        );
    }

    #[\Override]
    public function find(InitialAccessTokenId $id): ?InitialAccessToken
    {
        /** @var TokenRow|null $row */
        $row = $this->database->fetchOne(
            'SELECT ' . self::COLUMNS . ' FROM initial_access_tokens WHERE id = :id',
            ['id' => $id->value],
        );

        return $row === null ? null : $this->hydrate($row);
    }

    #[\Override]
    public function save(InitialAccessToken $token): void
    {
        $this->database->execute(
            'UPDATE initial_access_tokens SET revoked_at = :revoked_at WHERE id = :id',
            [
                'id' => $token->id->value,
                'revoked_at' => $token->revokedAt === null ? null : Timestamp::toDatabase($token->revokedAt),
            ],
        );
    }

    #[\Override]
    public function page(PageRequest $request): Page
    {
        $search = Search::across($request, ['description']);
        /** @var int|string $total */
        $total = $this->database->fetchValue(
            'SELECT count(*) FROM initial_access_tokens ' . $search->where,
            $search->parameters,
        );
        /** @var list<TokenRow> $rows */
        $rows = $this->database->fetchAll(
            'SELECT ' . self::COLUMNS . ' FROM initial_access_tokens ' . $search->where
            . ' ORDER BY created_at DESC, id LIMIT :limit OFFSET :offset',
            $search->pageParameters($request),
        );

        return new Page(array_map($this->hydrate(...), $rows), max(0, (int) $total), $request);
    }

    #[\Override]
    public function spendOne(Digest $digest, DateTimeImmutable $now): ?InitialAccessTokenId
    {
        /** @var string|null $id */
        $id = $this->database->fetchValue(
            <<<'SQL'
                UPDATE initial_access_tokens SET uses = uses + 1
                WHERE token_hash = :token_hash
                  AND revoked_at IS NULL
                  AND expires_at > :now
                  AND uses < max_uses
                RETURNING id
                SQL,
            ['token_hash' => $digest->toString(), 'now' => Timestamp::toDatabase($now)],
        );

        return $id === null ? null : InitialAccessTokenId::fromString($id);
    }

    /** @param TokenRow $row */
    private function hydrate(array $row): InitialAccessToken
    {
        return InitialAccessToken::reconstitute(
            InitialAccessTokenId::fromString($row['id']),
            Digest::fromHex($row['token_hash']),
            $row['description'],
            Timestamp::fromDatabase($row['created_at']),
            Timestamp::fromDatabase($row['expires_at']),
            $row['max_uses'],
            $row['uses'],
            $row['revoked_at'] === null ? null : Timestamp::fromDatabase($row['revoked_at']),
        );
    }
}
