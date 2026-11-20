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
use Clavia\Domain\OAuth2\AccessToken;
use Clavia\Domain\OAuth2\AccessTokenId;
use Clavia\Domain\OAuth2\AccessTokenRepository;
use Clavia\Domain\OAuth2\AuthorizationCodeId;
use Clavia\Domain\Shared\Audience;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\ScopeSet;
use DateTimeImmutable;

/**
 * Access tokens in the `oauth2_access_tokens` table.
 */
final readonly class PhpDbAccessTokenRepository implements AccessTokenRepository
{
    public function __construct(private Database $database)
    {
    }

    #[\Override]
    public function add(AccessToken $token): void
    {
        $this->database->execute(
            <<<'SQL'
                INSERT INTO oauth2_access_tokens (
                    id, token_hash, client_id, user_id, authorization_code_id, audience, token_type, scope,
                    issued_at, expires_at, revoked_at
                ) VALUES (
                    :id, :token_hash, :client_id, :user_id, :authorization_code_id, :audience, :token_type, :scope,
                    :issued_at, :expires_at, :revoked_at
                )
                SQL,
            [
                'id' => $token->id->value,
                'token_hash' => $token->digest->toString(),
                'client_id' => $token->clientId->value,
                'user_id' => $token->userId?->value,
                'authorization_code_id' => $token->authorizationCodeId?->value,
                'audience' => $token->audience?->value,
                'token_type' => AccessToken::TOKEN_TYPE,
                'scope' => $token->scope->toString(),
                'issued_at' => Timestamp::toDatabase($token->issuedAt),
                'expires_at' => Timestamp::toDatabase($token->expiresAt),
                'revoked_at' => Timestamp::toDatabaseOrNull($token->revokedAt()),
            ],
        );
    }

    #[\Override]
    public function findByDigest(Digest $digest): ?AccessToken
    {
        /**
         * @var array{id: string, token_hash: string, client_id: string, user_id: string|null,
         *            authorization_code_id: string|null, audience: string|null, scope: string, issued_at: string,
         *            expires_at: string, revoked_at: string|null}|null $row
         */
        $row = $this->database->fetchOne(
            <<<'SQL'
                SELECT id, token_hash, client_id, user_id, authorization_code_id, audience, scope,
                       issued_at, expires_at, revoked_at
                FROM oauth2_access_tokens
                WHERE token_hash = :token_hash
                SQL,
            ['token_hash' => $digest->toString()],
        );

        if ($row === null) {
            return null;
        }

        return AccessToken::reconstitute(
            AccessTokenId::fromString($row['id']),
            Digest::fromHex($row['token_hash']),
            ClientId::fromString($row['client_id']),
            $row['user_id'] === null ? null : UserId::fromString($row['user_id']),
            $row['authorization_code_id'] === null
                ? null
                : AuthorizationCodeId::fromString($row['authorization_code_id']),
            $row['audience'] === null ? null : Audience::fromString($row['audience']),
            ScopeSet::fromString($row['scope']),
            Timestamp::fromDatabase($row['issued_at']),
            Timestamp::fromDatabase($row['expires_at']),
            Timestamp::fromDatabaseOrNull($row['revoked_at']),
        );
    }

    #[\Override]
    public function revokeIssuedFrom(AuthorizationCodeId $code, DateTimeImmutable $now): int
    {
        return $this->database->execute(
            <<<'SQL'
                UPDATE oauth2_access_tokens
                SET revoked_at = :now
                WHERE authorization_code_id = :code_id AND revoked_at IS NULL
                SQL,
            ['now' => Timestamp::toDatabase($now), 'code_id' => $code->value],
        );
    }
}
