<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Persistence\PhpDb;

use Clavia\Domain\Authentication\AuthenticationContext;
use Clavia\Domain\Authentication\AuthenticationMethod;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\OAuth2\AuthorizationCode;
use Clavia\Domain\OAuth2\AuthorizationCodeId;
use Clavia\Domain\OAuth2\AuthorizationCodeRepository;
use Clavia\Domain\OAuth2\CodeChallenge;
use Clavia\Domain\Oidc\Nonce;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\ScopeSet;
use LogicException;

/**
 * Authorization codes in the `oauth2_authorization_codes` table.
 */
final readonly class PhpDbAuthorizationCodeRepository implements AuthorizationCodeRepository
{
    public function __construct(private Database $database)
    {
    }

    #[\Override]
    public function add(AuthorizationCode $code): void
    {
        $this->database->execute(
            <<<'SQL'
                INSERT INTO oauth2_authorization_codes (
                    id, code_hash, client_id, user_id, redirect_uri, scope, code_challenge,
                    code_challenge_method, nonce, auth_time, amr, expires_at, used_at, created_at
                ) VALUES (
                    :id, :code_hash, :client_id, :user_id, :redirect_uri, :scope, :code_challenge,
                    :code_challenge_method, :nonce, :auth_time, CAST(:amr AS jsonb), :expires_at, :used_at,
                    :created_at
                )
                SQL,
            [
                'id' => $code->id->value,
                'code_hash' => $code->digest->toString(),
                'client_id' => $code->clientId->value,
                'user_id' => $code->userId->value,
                'redirect_uri' => $code->redirectUri,
                'scope' => $code->scope->toString(),
                'code_challenge' => $code->challenge->value,
                'code_challenge_method' => CodeChallenge::METHOD,
                'nonce' => $code->nonce?->value,
                'auth_time' => Timestamp::toDatabaseOrNull($code->authentication->authenticatedAt),
                'amr' => Jsonb::encode($code->authentication->methodValues()),
                'expires_at' => Timestamp::toDatabase($code->expiresAt),
                'used_at' => Timestamp::toDatabaseOrNull($code->usedAt()),
                'created_at' => Timestamp::toDatabase($code->createdAt),
            ],
        );
    }

    #[\Override]
    public function lockForRedemption(Digest $digest): ?AuthorizationCode
    {
        // Outside a transaction the lock would be released as soon as the statement
        // ended, and two redemptions could both read an unspent code.
        if (! $this->database->inTransaction()) {
            throw new LogicException('An authorization code can only be locked inside a transaction.');
        }

        /**
         * @var array{id: string, code_hash: string, client_id: string, user_id: string, redirect_uri: string,
         *            scope: string, code_challenge: string, nonce: string|null, auth_time: string|null,
         *            amr: string, expires_at: string, used_at: string|null, created_at: string}|null $row
         */
        $row = $this->database->fetchOne(
            <<<'SQL'
                SELECT id, code_hash, client_id, user_id, redirect_uri, scope, code_challenge,
                       nonce, auth_time, amr, expires_at, used_at, created_at
                FROM oauth2_authorization_codes
                WHERE code_hash = :code_hash
                FOR UPDATE
                SQL,
            ['code_hash' => $digest->toString()],
        );

        if ($row === null) {
            return null;
        }

        return AuthorizationCode::reconstitute(
            AuthorizationCodeId::fromString($row['id']),
            Digest::fromHex($row['code_hash']),
            ClientId::fromString($row['client_id']),
            UserId::fromString($row['user_id']),
            $row['redirect_uri'],
            ScopeSet::fromString($row['scope']),
            CodeChallenge::fromString($row['code_challenge']),
            $row['nonce'] === null ? null : Nonce::fromString($row['nonce']),
            AuthenticationContext::reconstitute(
                Timestamp::fromDatabaseOrNull($row['auth_time']),
                array_map(AuthenticationMethod::from(...), Jsonb::decodeStrings($row['amr'])),
            ),
            Timestamp::fromDatabase($row['expires_at']),
            Timestamp::fromDatabaseOrNull($row['used_at']),
            Timestamp::fromDatabase($row['created_at']),
        );
    }

    #[\Override]
    public function save(AuthorizationCode $code): void
    {
        $this->database->execute(
            'UPDATE oauth2_authorization_codes SET used_at = :used_at WHERE id = :id',
            ['id' => $code->id->value, 'used_at' => Timestamp::toDatabaseOrNull($code->usedAt())],
        );
    }
}
