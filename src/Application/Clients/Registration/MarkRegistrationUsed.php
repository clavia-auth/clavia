<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Clients\Registration;

use Clavia\Application\Event\EventSubscriber;
use Clavia\Domain\Client\Registration\ClientRegistrationRepository;
use Clavia\Domain\OAuth2\Event\AccessTokenIssued;

/**
 * Records when a self-registered client was first issued a token (docs/design/
 * dynamic-client-registration.md §5.4), so {@see PurgeUnusedRegistrations} keeps it for good.
 *
 * Listens to `AccessTokenIssued`, which every grant dispatches, so no grant changes. One
 * conditional write per token, a no-op for an operator's client and after the first. It records
 * nothing in the audit trail: the token's own event already does.
 */
final readonly class MarkRegistrationUsed implements EventSubscriber
{
    public function __construct(private ClientRegistrationRepository $registrations)
    {
    }

    #[\Override]
    public function subscriptions(): array
    {
        return [AccessTokenIssued::class => $this->tokenIssued(...)];
    }

    private function tokenIssued(AccessTokenIssued $event): void
    {
        $this->registrations->markUsed($event->token->clientId, $event->token->issuedAt);
    }
}
