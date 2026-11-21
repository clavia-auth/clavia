<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Audit;

use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Shared\InvalidValue;
use DateTimeImmutable;

/**
 * Which events to read: every condition given must hold; none given reads them all.
 */
final readonly class AuditQuery
{
    /**
     * @param list<AuditEventType> $types       Any of these; empty for every type.
     * @param UserId|null          $actorUserId The person who acted.
     * @param ClientId|null        $clientId    The application that acted, or that a person acted through.
     * @param AuditTarget|null     $target      What it was about.
     * @param DateTimeImmutable|null $since     From this instant, included.
     * @param DateTimeImmutable|null $until     Up to this instant, excluded.
     *
     * @throws InvalidValue When the period ends before it starts.
     */
    public function __construct(
        public array $types = [],
        public ?UserId $actorUserId = null,
        public ?ClientId $clientId = null,
        public ?AuditTarget $target = null,
        public ?Outcome $outcome = null,
        public ?DateTimeImmutable $since = null,
        public ?DateTimeImmutable $until = null,
    ) {
        if ($since !== null && $until !== null && $until <= $since) {
            throw new InvalidValue('The period of an audit query ends after it starts.');
        }
    }
}
