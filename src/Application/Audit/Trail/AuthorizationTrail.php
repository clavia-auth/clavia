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
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Consent\Event\ConsentGiven;
use Clavia\Domain\Consent\Event\ConsentRefused;
use Clavia\Domain\Consent\Event\ConsentWithdrawn;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\OAuth2\Event\AccessTokenIssued;
use Clavia\Domain\OAuth2\Event\AccessTokenRevoked;
use Clavia\Domain\OAuth2\Event\AuthorizationCodeReplayed;
use Clavia\Domain\OAuth2\Event\DeviceRequestApproved;
use Clavia\Domain\OAuth2\Event\DeviceRequestRefused;
use Clavia\Domain\OAuth2\Event\RefreshTokenReplayed;
use Clavia\Domain\OAuth2\Event\RefreshTokenRevoked;

/**
 * Consents, device approvals, tokens issued, given back and replayed — in the audit trail.
 *
 * A token is recorded by its grant, its client, its scope and its audience, never by its
 * value. A person's token names them as both target and actor, through the client; a
 * machine's names the client. A replay is recorded as a failure, by nobody: whoever
 * presented the spent code or token is exactly who is not known.
 */
final readonly class AuthorizationTrail implements EventSubscriber
{
    public function __construct(private Audit $audit)
    {
    }

    #[\Override]
    public function subscriptions(): array
    {
        return [
            ConsentGiven::class => $this->consentGiven(...),
            ConsentRefused::class => $this->consentRefused(...),
            ConsentWithdrawn::class => $this->consentWithdrawn(...),
            DeviceRequestApproved::class => $this->deviceRequestApproved(...),
            DeviceRequestRefused::class => $this->deviceRequestRefused(...),
            AccessTokenIssued::class => $this->accessTokenIssued(...),
            AuthorizationCodeReplayed::class => $this->authorizationCodeReplayed(...),
            RefreshTokenReplayed::class => $this->refreshTokenReplayed(...),
            AccessTokenRevoked::class => $this->accessTokenRevoked(...),
            RefreshTokenRevoked::class => $this->refreshTokenRevoked(...),
        ];
    }

    private function consentGiven(ConsentGiven $event): void
    {
        $this->audit->record(AuditEventType::ConsentGiven, AuditTarget::client($event->clientId), [
            'scope' => $event->scope->toString(),
            'resource_server_id' => $event->resourceServerId?->value,
        ], Actor::person($event->userId, $event->clientId));
    }

    private function consentRefused(ConsentRefused $event): void
    {
        $this->audit->record(AuditEventType::ConsentRefused, AuditTarget::client($event->clientId), [
            'scope' => $event->scope->toString(),
            'resource_server_id' => $event->resourceServerId?->value,
        ], Actor::person($event->userId, $event->clientId));
    }

    private function consentWithdrawn(ConsentWithdrawn $event): void
    {
        $this->audit->record(AuditEventType::ConsentWithdrawn, AuditTarget::user($event->userId), [
            'client_id' => $event->clientId->value,
        ]);
    }

    private function deviceRequestApproved(DeviceRequestApproved $event): void
    {
        $this->audit->record(AuditEventType::DeviceApproved, AuditTarget::client($event->clientId), [
            'scope' => $event->scope->toString(),
            'audience' => $event->audience?->value,
        ], Actor::person($event->userId, $event->clientId));
    }

    private function deviceRequestRefused(DeviceRequestRefused $event): void
    {
        $this->audit->record(AuditEventType::DeviceRefused, AuditTarget::client($event->clientId), [
            'scope' => $event->scope->toString(),
            'audience' => $event->audience?->value,
            'reason' => $event->holdsNothing ? 'no_permission' : 'refused',
        ], Actor::person($event->userId, $event->clientId));
    }

    private function accessTokenIssued(AccessTokenIssued $event): void
    {
        $token = $event->token;
        $this->audit->record(
            AuditEventType::TokenIssued,
            self::holder($token->clientId, $token->userId),
            [
                'grant_type' => $event->grant->value,
                'client_id' => $token->clientId->value,
                'scope' => $token->scope->toString(),
                'audience' => $token->audience?->value,
                'refreshable' => $event->withRefreshToken,
            ],
            $token->userId === null
                ? Actor::application($token->clientId)
                : Actor::person($token->userId, $token->clientId),
        );
    }

    private function authorizationCodeReplayed(AuthorizationCodeReplayed $event): void
    {
        $this->audit->refused(AuditEventType::CodeReplayed, AuditTarget::user($event->userId), [
            'client_id' => $event->issuedTo->value,
            'presented_by' => $event->presentedBy->value,
        ], Actor::anonymous($event->presentedBy));
    }

    private function refreshTokenReplayed(RefreshTokenReplayed $event): void
    {
        $this->audit->refused(AuditEventType::RefreshTokenReplayed, AuditTarget::user($event->userId), [
            'client_id' => $event->issuedTo->value,
            'presented_by' => $event->presentedBy->value,
        ], Actor::anonymous($event->presentedBy));
    }

    private function accessTokenRevoked(AccessTokenRevoked $event): void
    {
        $this->audit->record(AuditEventType::TokenRevoked, self::holder($event->clientId, $event->userId), [
            'kind' => 'access',
            'client_id' => $event->clientId->value,
        ], Actor::application($event->clientId));
    }

    private function refreshTokenRevoked(RefreshTokenRevoked $event): void
    {
        $this->audit->record(AuditEventType::TokenRevoked, AuditTarget::user($event->userId), [
            'kind' => 'refresh',
            'client_id' => $event->clientId->value,
        ], Actor::application($event->clientId));
    }

    /** Whom a token speaks for: its person, or the machine client acting as itself. */
    private static function holder(ClientId $clientId, ?UserId $userId): AuditTarget
    {
        return $userId === null ? AuditTarget::client($clientId) : AuditTarget::user($userId);
    }
}
