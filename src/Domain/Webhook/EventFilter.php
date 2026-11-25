<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Webhook;

use Clavia\Domain\Audit\AuditEventType;
use Clavia\Domain\Shared\InvalidValue;

/**
 * Which audit events an endpoint wants: some types, or all of them (`*`). A type that does not
 * exist is refused, so a typo is not a silent "never" (docs/design/webhooks.md §2, "Filtering").
 */
final readonly class EventFilter
{
    public const string ALL = '*';

    /** @param list<AuditEventType>|null $types Null for all. */
    private function __construct(private ?array $types)
    {
    }

    public static function all(): self
    {
        return new self(null);
    }

    /**
     * @param list<string> $names `['*']`, or event types as the audit trail names them.
     *
     * @throws InvalidValue
     */
    public static function fromStrings(array $names): self
    {
        if ($names === []) {
            throw new InvalidValue("An endpoint names the event types it wants, or '*' for all of them.");
        }
        if ($names === [self::ALL]) {
            return self::all();
        }
        $types = [];
        foreach ($names as $name) {
            $type = AuditEventType::tryFrom($name) ?? throw new InvalidValue(
                $name === self::ALL
                    ? "'*' stands alone: it is every event type."
                    : 'An event type the audit trail does not record is named.',
            );
            if ($type === AuditEventType::WebhookTested) {
                throw new InvalidValue("'webhook.tested' goes to the endpoint tested, and is not subscribed to.");
            }
            if (in_array($type, $types, true)) {
                throw new InvalidValue('An event type is named twice.');
            }
            $types[] = $type;
        }
        usort($types, static fn (AuditEventType $a, AuditEventType $b): int => strcmp($a->value, $b->value));

        return new self($types);
    }

    /** Never a test event: that goes to the endpoint tested alone, even past `*`. */
    public function matches(AuditEventType $type): bool
    {
        if ($type === AuditEventType::WebhookTested) {
            return false;
        }

        return $this->types === null || in_array($type, $this->types, true);
    }

    /** @return list<string> As the Management API and storage write it. */
    public function toStrings(): array
    {
        return $this->types === null
            ? [self::ALL]
            : array_map(static fn (AuditEventType $type): string => $type->value, $this->types);
    }
}
