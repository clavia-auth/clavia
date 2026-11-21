<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Management;

use Clavia\Application\Audit\ReadAuditEvents;
use Clavia\Domain\Audit\AuditEventType;
use Clavia\Domain\Audit\AuditQuery;
use Clavia\Domain\Audit\AuditTarget;
use Clavia\Domain\Audit\Outcome;
use Clavia\Domain\Audit\TargetType;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Shared\InvalidValue;
use DateTimeImmutable;
use Exception;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `GET /api/v1/audit-events`: the audit trail, newest first, read-only.
 *
 * Filters combine: `type` (several, comma-separated), `actor_user_id`, `client_id` (the
 * application that acted or was acted through), `target_type` with `target_id`,
 * `outcome`, and the period `since` (included) to `until` (excluded). The contract has
 * already checked each one's shape.
 */
final readonly class AuditEventsHandler implements RequestHandlerInterface
{
    public function __construct(
        private ReadAuditEvents $read,
        private ManagementResponder $responder,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $management = ManagementRequest::of($request);

        return $this->responder->json(ManagementViews::page(
            ($this->read)(self::query($management), Paging::fromRequest($management)),
            ManagementViews::auditEvent(...),
        ));
    }

    /**
     * @throws InvalidValue
     */
    private static function query(ManagementRequest $request): AuditQuery
    {
        $type = self::text($request, 'type');
        $actor = self::text($request, 'actor_user_id');
        $client = self::text($request, 'client_id');
        $targetType = self::text($request, 'target_type');
        $targetId = self::text($request, 'target_id');
        $outcome = self::text($request, 'outcome');
        if (($targetType === null) !== ($targetId === null)) {
            throw new InvalidValue("'target_type' and 'target_id' go together.");
        }

        return new AuditQuery(
            $type === null ? [] : array_map(self::type(...), explode(',', $type)),
            $actor === null ? null : UserId::fromString($actor),
            $client === null ? null : ClientId::fromString($client),
            $targetType === null || $targetId === null
                ? null
                : AuditTarget::of(TargetType::from($targetType), $targetId),
            $outcome === null ? null : Outcome::from($outcome),
            self::instant($request, 'since'),
            self::instant($request, 'until'),
        );
    }

    private static function type(string $value): AuditEventType
    {
        return AuditEventType::tryFrom(trim($value))
            ?? throw new InvalidValue(sprintf("'%s' is not an audit event type.", trim($value)));
    }

    private static function text(ManagementRequest $request, string $name): ?string
    {
        /** @var mixed $value */
        $value = $request->query($name);

        return is_string($value) && $value !== '' ? $value : null;
    }

    /**
     * @throws InvalidValue
     */
    private static function instant(ManagementRequest $request, string $name): ?DateTimeImmutable
    {
        $value = self::text($request, $name);
        if ($value === null) {
            return null;
        }

        try {
            return new DateTimeImmutable($value);
        } catch (Exception) {
            throw new InvalidValue(sprintf("'%s' is an RFC 3339 date-time.", $name));
        }
    }
}
