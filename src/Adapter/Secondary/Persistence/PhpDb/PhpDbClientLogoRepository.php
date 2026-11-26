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
use Clavia\Domain\Client\ClientLogo;
use Clavia\Domain\Client\ClientLogoRepository;

/**
 * Applications' logos in `client_logos`, one row each, gone with the application (a cascade). The image is
 * `bytea`, carried in and out as base64 so no binary string crosses the driver.
 */
final readonly class PhpDbClientLogoRepository implements ClientLogoRepository
{
    public function __construct(private Database $database)
    {
    }

    #[\Override]
    public function save(ClientLogo $logo): void
    {
        $this->database->execute(
            <<<'SQL'
                INSERT INTO client_logos (client_id, media_type, content, version)
                VALUES (:client_id, :media_type, decode(:content, 'base64'), :version)
                ON CONFLICT (client_id) DO UPDATE SET
                    media_type = EXCLUDED.media_type,
                    content = EXCLUDED.content,
                    version = EXCLUDED.version
                SQL,
            [
                'client_id' => $logo->clientId->value,
                'media_type' => $logo->mediaType,
                'content' => base64_encode($logo->content),
                'version' => $logo->version,
            ],
        );
    }

    #[\Override]
    public function find(ClientId $clientId): ?ClientLogo
    {
        /** @var array{content: string}|null $row */
        $row = $this->database->fetchOne(
            "SELECT encode(content, 'base64') AS content FROM client_logos WHERE client_id = :client_id",
            ['client_id' => $clientId->value],
        );

        return $row === null ? null : ClientLogo::restore($clientId, base64_decode($row['content']));
    }

    #[\Override]
    public function versionOf(ClientId $clientId): ?string
    {
        /** @var non-empty-string|null $version */
        $version = $this->database->fetchValue(
            'SELECT version FROM client_logos WHERE client_id = :client_id',
            ['client_id' => $clientId->value],
        );

        return $version;
    }

    #[\Override]
    public function versionsOf(array $clientIds): array
    {
        if ($clientIds === []) {
            return [];
        }
        /** @var list<array{client_id: string, version: non-empty-string}> $rows */
        $rows = $this->database->fetchAll(
            'SELECT client_id, version FROM client_logos WHERE client_id IN (SELECT jsonb_array_elements_text('
            . 'CAST(:ids AS jsonb)))',
            ['ids' => json_encode(
                array_map(static fn (ClientId $id): string => $id->value, $clientIds),
                JSON_THROW_ON_ERROR,
            )],
        );
        $versions = [];
        foreach ($rows as $row) {
            $versions[$row['client_id']] = $row['version'];
        }

        return $versions;
    }

    #[\Override]
    public function delete(ClientId $clientId): bool
    {
        return $this->database->execute(
            'DELETE FROM client_logos WHERE client_id = :client_id',
            ['client_id' => $clientId->value],
        ) > 0;
    }
}
