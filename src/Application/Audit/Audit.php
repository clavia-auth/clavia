<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Audit;

use Clavia\Domain\Audit\Actor;
use Clavia\Domain\Audit\AuditEvent;
use Clavia\Domain\Audit\AuditEventId;
use Clavia\Domain\Audit\AuditEventType;
use Clavia\Domain\Audit\AuditLog;
use Clavia\Domain\Audit\AuditTarget;
use Clavia\Domain\Audit\Outcome;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\RandomSource;
use Clavia\Domain\Webhook\WebhookDeliveryRepository;
use LogicException;

/**
 * Writes audit events: what the trails (`Audit\Trail\*`) call for each domain event they
 * record. No use case calls it — a use case dispatches what happened, and the trails decide
 * what the audit trail says about it.
 *
 * The trail says what happened, to what, and — when it knows better than the request —
 * who did it (the person who just signed in). The rest comes from the {@see AuditContext}:
 * the caller the Management API authenticated, the request's address and user agent; at the
 * console, nobody, so the system. Events are dispatched synchronously, so the row is
 * appended through the same database as the change, inside the use case's transaction: it
 * commits or rolls back with it.
 */
final readonly class Audit
{
    public function __construct(
        private AuditLog $log,
        private AuditContext $context,
        private Clock $clock,
        private RandomSource $random,
        private WebhookDeliveryRepository $webhooks,
    ) {
    }

    /**
     * @param array<string, string|int|bool|list<string>|null> $details Never a credential.
     */
    public function record(
        AuditEventType $type,
        ?AuditTarget $target = null,
        array $details = [],
        ?Actor $actor = null,
        Outcome $outcome = Outcome::Success,
    ): void {
        try {
            $event = AuditEvent::record(
                AuditEventId::generate($this->random),
                $type,
                $this->clock->now(),
                $actor ?? $this->context->actor() ?? Actor::system(),
                $target,
                $outcome,
                $details,
                $this->context->clientAddress(),
                $this->context->userAgent(),
            );
        } catch (InvalidValue $mistake) {
            // Details are written by this codebase, not by a caller: a refusal is a bug.
            throw new LogicException('An audit event was recorded with invalid details.', 0, $mistake);
        }

        $this->log->append($event);
        // The webhook outbox, in the same transaction as the event: a rolled-back change sends
        // nothing, a committed one is never lost (docs/design/webhooks.md §5.2).
        $this->webhooks->enqueueFor($event, $event->occurredAt);
    }

    /**
     * A refusal: the same event, as a failure.
     *
     * @param array<string, string|int|bool|list<string>|null> $details Never a credential.
     */
    public function refused(
        AuditEventType $type,
        ?AuditTarget $target = null,
        array $details = [],
        ?Actor $actor = null,
    ): void {
        $this->record($type, $target, $details, $actor, Outcome::Failure);
    }
}
