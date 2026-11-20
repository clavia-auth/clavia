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
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\OAuth2\AuthorizationCodeId;
use Clavia\Domain\OAuth2\RefreshToken;
use Clavia\Domain\OAuth2\RefreshTokenId;
use Clavia\Domain\OAuth2\RefreshTokenRepository;
use Clavia\Domain\Shared\Audience;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\ScopeSet;
use DateTimeImmutable;
use LogicException;

/**
 * Refresh tokens in `oauth2_refresh_tokens`.
 *
 * @psalm-type RefreshTokenRow = array{id: string, token_hash: string, family_id: string, client_id: string,
 *     user_id: string, authorization_code_id: string|null, scope: string, audience: string|null,
 *     issued_at: string, expires_at: string, family_expires_at: string, used_at: string|null,
 *     revoked_at: string|null}
 */
final readonly class PhpDbRefreshTokenRepository implements RefreshTokenRepository
{
    private const string COLUMNS = 'id, token_hash, family_id, client_id, user_id, authorization_code_id, scope, '
        . 'audience, issued_at, expires_at, family_expires_at, used_at, revoked_at';

    public function __construct(private Database $database)
    {
    }

    #[\Override]
    public function add(RefreshToken $token): void
    {
        $this->database->execute(
            'INSERT INTO oauth2_refresh_tokens (' . self::COLUMNS . ') VALUES (:id, :token_hash, :family_id, '
            . ':client_id, :user_id, :authorization_code_id, :scope, :audience, :issued_at, :expires_at, '
            . ':family_expires_at, :used_at, :revoked_at)',
            [
                'id' => $token->id->value,
                'token_hash' => $token->digest->toString(),
                'family_id' => $token->familyId->value,
                'client_id' => $token->clientId->value,
                'user_id' => $token->userId->value,
                'authorization_code_id' => $token->authorizationCodeId?->value,
                'scope' => $token->scope->toString(),
                'audience' => $token->audience?->value,
                'issued_at' => Timestamp::toDatabase($token->issuedAt),
                'expires_at' => Timestamp::toDatabase($token->expiresAt),
                'family_expires_at' => Timestamp::toDatabase($token->familyExpiresAt),
                'used_at' => Timestamp::toDatabaseOrNull($token->usedAt()),
                'revoked_at' => Timestamp::toDatabaseOrNull($token->revokedAt()),
            ],
        );
    }

    #[\Override]
    public function findByDigest(Digest $digest): ?RefreshToken
    {
        return $this->one($digest, '');
    }

    #[\Override]
    public function lockForRefresh(Digest $digest): ?RefreshToken
    {
        // A lock outside a transaction is released by the statement that took it: it
        // would protect nothing.
        if (! $this->database->inTransaction()) {
            throw new LogicException('A refresh token can only be locked inside a transaction.');
        }

        return $this->one($digest, ' FOR UPDATE');
    }

    #[\Override]
    public function save(RefreshToken $token): void
    {
        // Only the spend changes a stored token; revocation is a statement on families.
        $this->database->execute(
            'UPDATE oauth2_refresh_tokens SET used_at = :used_at WHERE id = :id',
            ['used_at' => Timestamp::toDatabaseOrNull($token->usedAt()), 'id' => $token->id->value],
        );
    }

    #[\Override]
    public function revokeFamily(RefreshTokenId $family, DateTimeImmutable $now): int
    {
        return $this->database->execute(
            <<<'SQL'
                UPDATE oauth2_refresh_tokens
                SET revoked_at = :now
                WHERE family_id = :family_id AND revoked_at IS NULL
                SQL,
            ['now' => Timestamp::toDatabase($now), 'family_id' => $family->value],
        );
    }

    #[\Override]
    public function revokeIssuedFrom(AuthorizationCodeId $code, DateTimeImmutable $now): int
    {
        return $this->database->execute(
            <<<'SQL'
                UPDATE oauth2_refresh_tokens
                SET revoked_at = :now
                WHERE authorization_code_id = :code_id AND revoked_at IS NULL
                SQL,
            ['now' => Timestamp::toDatabase($now), 'code_id' => $code->value],
        );
    }

    private function one(Digest $digest, string $lock): ?RefreshToken
    {
        /** @var RefreshTokenRow|null $row */
        $row = $this->database->fetchOne(
            'SELECT ' . self::COLUMNS . ' FROM oauth2_refresh_tokens WHERE token_hash = :token_hash' . $lock,
            ['token_hash' => $digest->toString()],
        );

        return $row === null ? null : RefreshToken::reconstitute(
            RefreshTokenId::fromString($row['id']),
            Digest::fromHex($row['token_hash']),
            RefreshTokenId::fromString($row['family_id']),
            ClientId::fromString($row['client_id']),
            UserId::fromString($row['user_id']),
            $row['authorization_code_id'] === null
                ? null
                : AuthorizationCodeId::fromString($row['authorization_code_id']),
            ScopeSet::fromString($row['scope']),
            $row['audience'] === null ? null : Audience::fromString($row['audience']),
            Timestamp::fromDatabase($row['issued_at']),
            Timestamp::fromDatabase($row['expires_at']),
            Timestamp::fromDatabase($row['family_expires_at']),
            Timestamp::fromDatabaseOrNull($row['used_at']),
            Timestamp::fromDatabaseOrNull($row['revoked_at']),
        );
    }
}
