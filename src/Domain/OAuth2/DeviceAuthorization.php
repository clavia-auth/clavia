<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\OAuth2;

use Clavia\Domain\Authentication\AuthenticationContext;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Shared\Audience;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\ScopeSet;
use DateTimeImmutable;
use LogicException;

/**
 * A device's request for access, from the moment it asks (RFC 8628 §3.1) until its code
 * is redeemed or runs out.
 *
 * Two codes stand for it: the device code the device polls with — a secret, kept only as
 * a digest — and the user code a person types to find it. It moves from pending to
 * approved, with who approved it and how they were signed in so the ID token can say,
 * or to denied; nothing moves it back.
 *
 * Polling is held to the interval (§3.5): a device that polls sooner is told to slow
 * down, and its interval grows by five seconds for this and every later poll — so a
 * device that ignores `slow_down` backs itself further off.
 */
final class DeviceAuthorization
{
    /** RFC 8628 §3.5: what a `slow_down` adds to the interval. */
    public const int SLOW_DOWN_SECONDS = 5;

    /**
     * How long the request is kept after it expires, so a device that polls a little late
     * hears `expired_token` rather than the `invalid_grant` of an unknown code.
     */
    public const int EXPIRY_GRACE_SECONDS = 60;

    /**
     * @param positive-int $interval
     */
    private function __construct(
        public readonly Digest $deviceCode,
        public readonly UserCode $userCode,
        public readonly ClientId $clientId,
        public readonly ScopeSet $scope,
        public readonly ?Audience $audience,
        public readonly DateTimeImmutable $expiresAt,
        private int $interval,
        private DeviceDecision $decision,
        private ?DateTimeImmutable $lastPolledAt,
        private ?UserId $userId,
        private ?AuthenticationContext $authentication,
    ) {
    }

    /**
     * @param positive-int $lifetimeSeconds
     * @param positive-int $interval
     */
    public static function request(
        Digest $deviceCode,
        UserCode $userCode,
        ClientId $clientId,
        ScopeSet $scope,
        ?Audience $audience,
        DateTimeImmutable $now,
        int $lifetimeSeconds,
        int $interval,
    ): self {
        return new self(
            $deviceCode,
            $userCode,
            $clientId,
            $scope,
            $audience,
            $now->modify(sprintf('+%d seconds', $lifetimeSeconds)),
            $interval,
            DeviceDecision::Pending,
            null,
            null,
            null,
        );
    }

    /**
     * A request read back from storage.
     *
     * @param positive-int $interval
     *
     * @throws LogicException When a decided request names nobody, or a pending one somebody.
     */
    public static function reconstitute(
        Digest $deviceCode,
        UserCode $userCode,
        ClientId $clientId,
        ScopeSet $scope,
        ?Audience $audience,
        DateTimeImmutable $expiresAt,
        int $interval,
        DeviceDecision $decision,
        ?DateTimeImmutable $lastPolledAt,
        ?UserId $userId,
        ?AuthenticationContext $authentication,
    ): self {
        if (($decision === DeviceDecision::Pending) !== ($userId === null)) {
            throw new LogicException('A decided device request names who decided it, and only a decided one.');
        }

        return new self(
            $deviceCode,
            $userCode,
            $clientId,
            $scope,
            $audience,
            $expiresAt,
            $interval,
            $decision,
            $lastPolledAt,
            $userId,
            $authentication,
        );
    }

    /**
     * Record a poll, and say what the device should hear.
     *
     * Only a pending request is held to the interval: once decided, the answer is ready
     * whenever the device asks.
     */
    public function poll(DateTimeImmutable $now): DevicePoll
    {
        if ($this->isExpiredAt($now)) {
            return DevicePoll::Expired;
        }

        if ($this->decision === DeviceDecision::Denied) {
            return DevicePoll::Denied;
        }
        if ($this->decision === DeviceDecision::Approved) {
            return DevicePoll::Approved;
        }

        $tooSoon = $this->lastPolledAt !== null
            && $now->getTimestamp() - $this->lastPolledAt->getTimestamp() < $this->interval;
        $this->lastPolledAt = $now;
        if ($tooSoon) {
            $this->interval += self::SLOW_DOWN_SECONDS;

            return DevicePoll::SlowDown;
        }

        return DevicePoll::Pending;
    }

    /** Whether a person may still decide: pending, and not run out. */
    public function awaitsDecisionAt(DateTimeImmutable $now): bool
    {
        return $this->decision === DeviceDecision::Pending && ! $this->isExpiredAt($now);
    }

    /**
     * @throws LogicException When it is not awaiting a decision.
     */
    public function approve(UserId $userId, AuthenticationContext $authentication, DateTimeImmutable $now): void
    {
        $this->decide(DeviceDecision::Approved, $userId, $authentication, $now);
    }

    /**
     * @throws LogicException When it is not awaiting a decision.
     */
    public function deny(UserId $userId, DateTimeImmutable $now): void
    {
        $this->decide(DeviceDecision::Denied, $userId, null, $now);
    }

    public function isExpiredAt(DateTimeImmutable $now): bool
    {
        return $this->expiresAt <= $now;
    }

    /** @return positive-int */
    public function interval(): int
    {
        return $this->interval;
    }

    public function decision(): DeviceDecision
    {
        return $this->decision;
    }

    public function lastPolledAt(): ?DateTimeImmutable
    {
        return $this->lastPolledAt;
    }

    /** Who decided; null while pending. */
    public function userId(): ?UserId
    {
        return $this->userId;
    }

    /** How the person who approved was signed in; null unless approved. */
    public function authentication(): ?AuthenticationContext
    {
        return $this->authentication;
    }

    /**
     * How long storage must keep it from `$now`: its remaining life and the grace after.
     *
     * @return positive-int
     */
    public function retentionFrom(DateTimeImmutable $now): int
    {
        return max(1, $this->expiresAt->getTimestamp() - $now->getTimestamp() + self::EXPIRY_GRACE_SECONDS);
    }

    private function decide(
        DeviceDecision $decision,
        UserId $userId,
        ?AuthenticationContext $authentication,
        DateTimeImmutable $now,
    ): void {
        if (! $this->awaitsDecisionAt($now)) {
            throw new LogicException('Only a device request still awaiting a decision can be decided.');
        }

        $this->decision = $decision;
        $this->userId = $userId;
        $this->authentication = $authentication;
    }
}
