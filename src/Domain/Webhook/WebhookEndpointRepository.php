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
interface WebhookEndpointRepository
{
    public function find(WebhookEndpointId $id): ?WebhookEndpoint;

    /** @return list<WebhookEndpoint> Every endpoint, oldest first: there are at most twenty. */
    public function all(): array;

    public function count(): int;

    /** Insert the endpoint, or update it when it exists. */
    public function save(WebhookEndpoint $endpoint): void;

    public function delete(WebhookEndpointId $id): void;
}
