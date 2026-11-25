<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Persistence\PhpDb;

use Clavia\Domain\Shared\Url;
use Clavia\Domain\Webhook\EventFilter;
use Clavia\Domain\Webhook\WebhookEndpoint;
use Clavia\Domain\Webhook\WebhookEndpointId;
use Clavia\Domain\Webhook\WebhookEndpointRepository;

/**
 * Webhook endpoints in `webhook_endpoints`, their secrets as the sealed text the application gave:
 * this repository never sees a secret.
 *
 * @psalm-type EndpointRow = array{id: string, url: string, description: string, events: string,
 *     is_enabled: bool, secret_sealed: string, previous_secret_sealed: string|null,
 *     previous_secret_until: string|null, created_at: string, updated_at: string}
 */
final readonly class PhpDbWebhookEndpointRepository implements WebhookEndpointRepository
{
    private const string COLUMNS = 'id, url, description, events, is_enabled, secret_sealed, '
        . 'previous_secret_sealed, previous_secret_until, created_at, updated_at';

    public function __construct(private Database $database)
    {
    }

    #[\Override]
    public function find(WebhookEndpointId $id): ?WebhookEndpoint
    {
        /** @var EndpointRow|null $row */
        $row = $this->database->fetchOne(
            'SELECT ' . self::COLUMNS . ' FROM webhook_endpoints WHERE id = :id',
            ['id' => $id->value],
        );

        return $row === null ? null : self::hydrate($row);
    }

    #[\Override]
    public function all(): array
    {
        /** @var list<EndpointRow> $rows */
        $rows = $this->database->fetchAll(
            'SELECT ' . self::COLUMNS . ' FROM webhook_endpoints ORDER BY created_at, id',
        );

        return array_map(self::hydrate(...), $rows);
    }

    #[\Override]
    public function count(): int
    {
        /** @var int|string $count */
        $count = $this->database->fetchValue('SELECT count(*) FROM webhook_endpoints');

        return (int) $count;
    }

    #[\Override]
    public function save(WebhookEndpoint $endpoint): void
    {
        $this->database->execute(
            <<<'SQL'
                INSERT INTO webhook_endpoints (id, url, description, events, is_enabled, secret_sealed,
                    previous_secret_sealed, previous_secret_until, created_at, updated_at)
                VALUES (:id, :url, :description, CAST(:events AS jsonb), :is_enabled, :secret_sealed,
                    :previous_secret_sealed, :previous_secret_until, :created_at, :updated_at)
                ON CONFLICT (id) DO UPDATE SET
                    url = EXCLUDED.url,
                    description = EXCLUDED.description,
                    events = EXCLUDED.events,
                    is_enabled = EXCLUDED.is_enabled,
                    secret_sealed = EXCLUDED.secret_sealed,
                    previous_secret_sealed = EXCLUDED.previous_secret_sealed,
                    previous_secret_until = EXCLUDED.previous_secret_until,
                    updated_at = EXCLUDED.updated_at
                SQL,
            [
                'id' => $endpoint->id->value,
                'url' => $endpoint->url->value,
                'description' => $endpoint->description,
                'events' => Jsonb::encode($endpoint->events->toStrings()),
                'is_enabled' => $endpoint->isEnabled,
                'secret_sealed' => $endpoint->sealedSecret,
                'previous_secret_sealed' => $endpoint->sealedPreviousSecret,
                'previous_secret_until' => $endpoint->previousSecretUntil === null
                    ? null
                    : Timestamp::toDatabase($endpoint->previousSecretUntil),
                'created_at' => Timestamp::toDatabase($endpoint->createdAt),
                'updated_at' => Timestamp::toDatabase($endpoint->updatedAt),
            ],
        );
    }

    #[\Override]
    public function delete(WebhookEndpointId $id): void
    {
        $this->database->execute('DELETE FROM webhook_endpoints WHERE id = :id', ['id' => $id->value]);
    }

    /** @param EndpointRow $row */
    private static function hydrate(array $row): WebhookEndpoint
    {
        $sealed = $row['secret_sealed'];
        assert($sealed !== '');
        $previous = $row['previous_secret_sealed'];

        return WebhookEndpoint::reconstitute(
            WebhookEndpointId::fromString($row['id']),
            Url::fromString($row['url']),
            $row['description'],
            EventFilter::fromStrings(Jsonb::decodeStrings($row['events'])),
            $row['is_enabled'],
            $sealed,
            $previous === '' ? null : $previous,
            $row['previous_secret_until'] === null ? null : Timestamp::fromDatabase($row['previous_secret_until']),
            Timestamp::fromDatabase($row['created_at']),
            Timestamp::fromDatabase($row['updated_at']),
        );
    }
}
