<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Audit;

use Clavia\Domain\Audit\AuditEvent;
use DateTimeZone;

/**
 * An audit event as this server shows it to others: the Management API's `AuditEvent`, and the
 * `data` of a webhook delivery. One representation, so what a webhook sends is exactly what
 * `GET /api/v1/audit-events` returns, and holds nothing the trail does not (docs/design/webhooks.md §2).
 */
final readonly class AuditEventDocument
{
    private function __construct()
    {
    }

    /** @return array<string, mixed> */
    public static function of(AuditEvent $event): array
    {
        return [
            'id' => $event->id->value,
            'type' => $event->type->value,
            'occurred_at' => $event->occurredAt->setTimezone(new DateTimeZone('UTC'))->format('Y-m-d\TH:i:s\Z'),
            'outcome' => $event->outcome->value,
            'actor' => [
                'kind' => $event->actor->kind->value,
                'user_id' => $event->actor->userId?->value,
                'client_id' => $event->actor->clientId?->value,
                'provisioning_token_id' => $event->actor->provisioningTokenId?->value,
            ],
            'target' => $event->target === null
                ? null
                : ['type' => $event->target->type->value, 'id' => $event->target->id],
            'details' => (object) $event->details,
            'client_address' => $event->clientAddress,
            'user_agent' => $event->userAgent,
        ];
    }
}
