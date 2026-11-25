<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Webhook;

/** Where webhook endpoints are kept, their secrets sealed. */
use DateTimeImmutable;

interface WebhookEndpointRepository
{
    public function find(WebhookEndpointId $id): ?WebhookEndpoint;

    /** @return list<WebhookEndpoint> Every endpoint, oldest first: there are at most twenty. */
    public function all(): array;

    public function count(): int;

    /** Insert the endpoint, or update it when it exists. */
    public function save(WebhookEndpoint $endpoint): void;

    public function delete(WebhookEndpointId $id): void;

    /**
     * A delivery to it failed: it is failing since now, unless it already was. A conditional write,
     * so the worker never overwrites what an operator just changed.
     */
    public function recordFailure(WebhookEndpointId $id, DateTimeImmutable $now): void;

    /** A delivery to it succeeded: it is no longer failing. */
    public function recordSuccess(WebhookEndpointId $id): void;

    /**
     * Switch it off as dead if it is enabled and has been failing since before `$before`.
     *
     * @return bool Whether this call switched it off.
     */
    #[\NoDiscard]
    public function disableIfFailingSince(
        WebhookEndpointId $id,
        DateTimeImmutable $before,
        DateTimeImmutable $now,
    ): bool;
}
