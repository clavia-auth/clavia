<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Signing\Postgres;

use Clavia\Adapter\Secondary\Persistence\PhpDb\Jsonb;
use Clavia\Adapter\Secondary\Persistence\PhpDb\Timestamp;
use Clavia\Domain\Oidc\PublicJwk;
use Clavia\Domain\Oidc\SigningKey;
use Clavia\Domain\Oidc\SigningKeyStatus;

/**
 * The public columns of an `oidc_signing_keys` row, and the {@see SigningKey} they
 * describe. The sealed private key is not among them.
 */
final class SigningKeyRow
{
    public const string COLUMNS = 'public_jwk, status, created_at, retired_at, published_until';

    /** The active key first, then the others newest first. */
    public const string ORDER = "ORDER BY status = 'active' DESC, created_at DESC, kid";

    private function __construct()
    {
    }

    /**
     * @param array<string, mixed> $row
     */
    public static function hydrate(array $row): SigningKey
    {
        /**
         * @var array{public_jwk: string, status: string, created_at: string, retired_at: string|null,
         *            published_until: string|null} $row
         */
        return SigningKey::reconstitute(
            PublicJwk::fromArray(Jsonb::decodeObject($row['public_jwk'])),
            SigningKeyStatus::from($row['status']),
            Timestamp::fromDatabase($row['created_at']),
            Timestamp::fromDatabaseOrNull($row['retired_at']),
            Timestamp::fromDatabaseOrNull($row['published_until']),
        );
    }
}
