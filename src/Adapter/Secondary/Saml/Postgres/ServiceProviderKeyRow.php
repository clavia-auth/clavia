<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Saml\Postgres;

use Clavia\Adapter\Secondary\Persistence\PhpDb\Timestamp;
use Clavia\Domain\Connection\Saml\ServiceProviderKey;
use Clavia\Domain\Connection\Saml\ServiceProviderKeySet;
use Clavia\Domain\Connection\Saml\ServiceProviderKeyStatus;
use Clavia\Domain\Connection\Saml\ServiceProviderKeyUsage;

/**
 * A row of `saml_service_provider_keys`, read the same way by the store and the keys: never the
 * sealed private half, which only `sign()` and `decryptKey()` select.
 *
 * @psalm-type KeyRow = array{kid: non-empty-string, usage: string, status: string,
 *     certificate: non-empty-string, valid_until: string, created_at: string, promoted_at: string|null,
 *     retired_at: string|null}
 */
final readonly class ServiceProviderKeyRow
{
    public const string COLUMNS = 'kid, usage, status, certificate, valid_until, created_at, promoted_at, retired_at';

    private function __construct()
    {
    }

    /** @param list<array<string, mixed>> $rows */
    public static function set(array $rows): ServiceProviderKeySet
    {
        /** @var list<KeyRow> $rows */
        return ServiceProviderKeySet::of(array_map(self::hydrate(...), $rows));
    }

    /** @param KeyRow $row */
    private static function hydrate(array $row): ServiceProviderKey
    {
        return ServiceProviderKey::reconstitute(
            $row['kid'],
            ServiceProviderKeyUsage::from($row['usage']),
            ServiceProviderKeyStatus::from($row['status']),
            $row['certificate'],
            Timestamp::fromDatabase($row['valid_until']),
            Timestamp::fromDatabase($row['created_at']),
            Timestamp::fromDatabaseOrNull($row['promoted_at']),
            Timestamp::fromDatabaseOrNull($row['retired_at']),
        );
    }
}
