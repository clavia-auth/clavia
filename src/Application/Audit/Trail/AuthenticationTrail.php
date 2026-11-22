<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Audit\Trail;

use Clavia\Application\Audit\Audit;
use Clavia\Application\Event\EventSubscriber;
use Clavia\Domain\Audit\Actor;
use Clavia\Domain\Audit\AuditEventType;
use Clavia\Domain\Audit\AuditTarget;
use Clavia\Domain\Authentication\AuthenticationMethod;
use Clavia\Domain\Authentication\Event\PasskeyCounterRegressed;
use Clavia\Domain\Authentication\Event\PasskeyRegistered;
use Clavia\Domain\Authentication\Event\PasskeyRemoved;
use Clavia\Domain\Authentication\Event\PasskeyRenamed;
use Clavia\Domain\Authentication\Event\SecondFactorEnrolled;
use Clavia\Domain\Authentication\Event\SecondFactorRemoved;
use Clavia\Domain\Authentication\Event\SessionsEnded;
use Clavia\Domain\Authentication\Event\SignedIn;
use Clavia\Domain\Authentication\Event\SignInRefused;
use Clavia\Domain\Connection\ConnectionName;

/**
 * Sign-ins, refusals, sessions ended, second factors and passkeys — in the audit trail.
 *
 * A refusal names nobody as its actor: whoever typed the password is not known to be the
 * account's owner. Ending a session is the person's act when they signed out, and the
 * request's caller (an operator, the console) otherwise.
 */
final readonly class AuthenticationTrail implements EventSubscriber
{
    private const string TOTP = 'totp';

    public function __construct(private Audit $audit)
    {
    }

    #[\Override]
    public function subscriptions(): array
    {
        return [
            SignedIn::class => $this->signedIn(...),
            SignInRefused::class => $this->signInRefused(...),
            SessionsEnded::class => $this->sessionsEnded(...),
            SecondFactorEnrolled::class => $this->secondFactorEnrolled(...),
            SecondFactorRemoved::class => $this->secondFactorRemoved(...),
            PasskeyRegistered::class => $this->passkeyRegistered(...),
            PasskeyRenamed::class => $this->passkeyRenamed(...),
            PasskeyRemoved::class => $this->passkeyRemoved(...),
            PasskeyCounterRegressed::class => $this->passkeyCounterRegressed(...),
        ];
    }

    private function signedIn(SignedIn $event): void
    {
        $session = $event->session;
        $this->audit->record(AuditEventType::SignedIn, AuditTarget::user($session->userId), [
            'amr' => array_map(static fn (AuthenticationMethod $method): string => $method->value, $session->methods),
            'connection' => $session->connection->value,
            'sid' => $session->sid,
        ], Actor::person($session->userId));
    }

    private function signInRefused(SignInRefused $event): void
    {
        $connection = $event->connection;
        $this->audit->refused(
            AuditEventType::SignInFailed,
            $event->userId === null ? null : AuditTarget::user($event->userId),
            [
                'method' => $event->method?->value,
                'reason' => $event->reason->value,
                'email' => $event->email,
                'connection' => $connection instanceof ConnectionName ? $connection->value : null,
            ],
            Actor::anonymous($event->clientId),
        );
    }

    private function sessionsEnded(SessionsEnded $event): void
    {
        foreach ($event->sessions as $session) {
            $this->audit->record(
                AuditEventType::SessionEnded,
                AuditTarget::user($session->userId),
                ['reason' => $event->reason->value, 'sid' => $session->sid],
                $event->reason->byThePerson() ? Actor::person($session->userId, $event->via) : null,
            );
        }
    }

    private function secondFactorEnrolled(SecondFactorEnrolled $event): void
    {
        $this->audit->record(
            AuditEventType::MfaEnrolled,
            AuditTarget::user($event->userId),
            ['factor' => self::TOTP],
            Actor::person($event->userId),
        );
    }

    private function secondFactorRemoved(SecondFactorRemoved $event): void
    {
        $this->audit->record(
            AuditEventType::MfaRemoved,
            AuditTarget::user($event->userId),
            ['factor' => self::TOTP, 'reset' => ! $event->byTheirOwner],
            $event->byTheirOwner ? Actor::person($event->userId) : null,
        );
    }

    /** The passkey is named and described, never its credential id or its key. */
    private function passkeyRegistered(PasskeyRegistered $event): void
    {
        $this->audit->record(AuditEventType::PasskeyRegistered, AuditTarget::user($event->userId), [
            'passkey' => $event->passkeyId->value,
            'name' => $event->name->value,
            'synced' => $event->synced,
            'aaguid' => $event->aaguid?->value,
        ], Actor::person($event->userId));
    }

    private function passkeyRenamed(PasskeyRenamed $event): void
    {
        $this->audit->record(AuditEventType::PasskeyRenamed, AuditTarget::user($event->userId), [
            'passkey' => $event->passkeyId->value,
            'name' => $event->name->value,
        ], Actor::person($event->userId));
    }

    /** An operator's removal is the request's caller's, and says so. */
    private function passkeyRemoved(PasskeyRemoved $event): void
    {
        $this->audit->record(
            AuditEventType::PasskeyRemoved,
            AuditTarget::user($event->userId),
            [
                'passkey' => $event->passkeyId->value,
                'name' => $event->name->value,
                'by_operator' => ! $event->byTheirOwner,
            ],
            $event->byTheirOwner ? Actor::person($event->userId) : null,
        );
    }

    /** Whoever presented it is not known to be the account's owner: no actor, as for a wrong password. */
    private function passkeyCounterRegressed(PasskeyCounterRegressed $event): void
    {
        $this->audit->refused(
            AuditEventType::PasskeyCounterRegressed,
            AuditTarget::user($event->userId),
            [
                'passkey' => $event->passkeyId->value,
                'name' => $event->name->value,
                'stored' => $event->storedCounter,
                'presented' => $event->presentedCounter,
            ],
            Actor::anonymous(),
        );
    }
}
