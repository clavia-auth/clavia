<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Audit;

use Clavia\Domain\Shared\InvalidValue;
use DateTimeImmutable;

/**
 * One entry of the audit trail: what happened, when, who did it, to what, whether it
 * succeeded, and from where.
 *
 * Written once and never changed. Its details are a flat map of short values — a grant
 * type, a scope, a reason — and **never a credential**: a key that names one (`secret`,
 * `password`, `token`…) is refused here, so no call site can leak one into the trail by
 * accident. The trail is read by operators and kept for months; what it says must be safe
 * to show.
 */
final readonly class AuditEvent
{
    /** Fragments no detail key may contain. */
    public const array FORBIDDEN_KEY_FRAGMENTS = [
        'secret',
        'password',
        'passwd',
        'token',
        'credential',
        'assertion',
        'verifier',
        'private',
        'cookie',
    ];

    public const int MAX_DETAILS = 16;

    public const int MAX_VALUE_LENGTH = 512;

    /**
     * @param array<non-empty-string, string|int|bool|list<string>> $details
     */
    private function __construct(
        public AuditEventId $id,
        public AuditEventType $type,
        public DateTimeImmutable $occurredAt,
        public Actor $actor,
        public ?AuditTarget $target,
        public Outcome $outcome,
        public array $details,
        public ?string $clientAddress,
        public ?string $userAgent,
    ) {
    }

    /**
     * @param array<string, string|int|bool|list<string>|null> $details Null values are left out.
     * @param string|null $clientAddress Where the request came from; null at the console.
     * @param string|null $userAgent     What the browser or client said it was, cut to 512 bytes.
     *
     * @throws InvalidValue When a detail's name is malformed or names a credential, or there are
     *                      more than 16. Values longer than 512 bytes are cut, lists to 16 items.
     */
    public static function record(
        AuditEventId $id,
        AuditEventType $type,
        DateTimeImmutable $occurredAt,
        Actor $actor,
        ?AuditTarget $target,
        Outcome $outcome,
        array $details = [],
        ?string $clientAddress = null,
        ?string $userAgent = null,
    ): self {
        return new self(
            $id,
            $type,
            $occurredAt,
            $actor,
            $target,
            $outcome,
            self::checked($details),
            $clientAddress,
            $userAgent === null ? null : self::cut($userAgent),
        );
    }

    /**
     * @param array<string, string|int|bool|list<string>|null> $details
     *
     * @return array<non-empty-string, string|int|bool|list<string>>
     *
     * @throws InvalidValue
     */
    private static function checked(array $details): array
    {
        $details = array_filter($details, static fn (mixed $value): bool => $value !== null);
        if (count($details) > self::MAX_DETAILS) {
            throw new InvalidValue(sprintf('An audit event carries at most %d details.', self::MAX_DETAILS));
        }

        $checked = [];
        foreach ($details as $key => $value) {
            if (preg_match('/^[a-z][a-z0-9_]{0,63}$/D', $key) !== 1) {
                throw new InvalidValue(sprintf("'%s' is not an audit detail name (snake_case, at most 64).", $key));
            }
            foreach (self::FORBIDDEN_KEY_FRAGMENTS as $fragment) {
                if (str_contains($key, $fragment)) {
                    throw new InvalidValue(sprintf("The audit trail never holds a credential: '%s' is refused.", $key));
                }
            }
            // Values may come from a request (an address typed at the login page): they are cut
            // to size, never refused — a failed sign-in must be recorded, not turned into an error.
            $checked[$key] = match (true) {
                is_string($value) => self::cut($value),
                is_array($value) => array_map(self::cut(...), array_slice($value, 0, self::MAX_DETAILS)),
                default => $value,
            };
        }

        /** @var array<non-empty-string, string|int|bool|list<string>> $checked */
        return $checked;
    }

    private static function cut(string $value): string
    {
        return mb_strcut($value, 0, self::MAX_VALUE_LENGTH, 'UTF-8');
    }
}
