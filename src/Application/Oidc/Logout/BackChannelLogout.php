<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Oidc\Logout;

use Clavia\Application\Event\EventSubscriber;
use Clavia\Application\Oidc\CompactJws;
use Clavia\Application\Port\BackChannelLogoutDelivery;
use Clavia\Application\Port\DeferredTasks;
use Clavia\Application\Port\NoActiveSigningKey;
use Clavia\Application\Port\SigningFailed;
use Clavia\Application\Port\TokenSigner;
use Clavia\Domain\Authentication\Event\SessionsEnded;
use Clavia\Domain\Authentication\Session;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Oidc\LogoutTokenClaims;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\SecretGenerator;

/**
 * Tell the applications that signed in through a session that it has ended (OIDC
 * Back-Channel Logout 1.0).
 *
 * Signing out here ends the browser session at `auth.*`; every application that signed
 * in through it still holds a session of its own and, untold, keeps it. So each one that
 * registered a back-channel logout URI is sent a logout token naming the session — the
 * `sid` its ID tokens carried — and the person.
 *
 * After the response, one delivery per application: the person signing out does not wait
 * on somebody else's server, and one application being down is no reason to leave the
 * others signed in. What notifies is every way a session is *ended*: the two logout
 * endpoints, an operator, an account deactivated or deleted. What does not: a session
 * running out on its own (nothing runs when a key lapses), and the quiet replacement of a
 * session when the same browser signs in again — the person did not leave. Those are the
 * use cases that dispatch {@see SessionsEnded}, which this subscribes to.
 */
final readonly class BackChannelLogout implements EventSubscriber
{
    /**
     * @param non-empty-string $issuer          The issuer identifier, exactly as discovery states it.
     * @param positive-int     $lifetimeSeconds How long a logout token is valid
     *                                          (`CLAVIA_BACKCHANNEL_LOGOUT_TOKEN_LIFETIME`): it is
     *                                          consumed on receipt.
     */
    public function __construct(
        private ClientRepository $clients,
        private TokenSigner $signer,
        private CompactJws $jws,
        private BackChannelLogoutDelivery $delivery,
        private DeferredTasks $deferred,
        private SecretGenerator $secrets,
        private Clock $clock,
        private string $issuer,
        private int $lifetimeSeconds,
    ) {
    }

    #[\Override]
    public function subscriptions(): array
    {
        return [SessionsEnded::class => $this->sessionsEnded(...)];
    }

    /**
     * Schedule the logout tokens for the ended sessions — none for a session no
     * application signed in through. The sessions are already gone from the store (it is
     * not transactional), so they are reported whatever the rest of the request does.
     */
    private function sessionsEnded(SessionsEnded $event): void
    {
        foreach ($event->sessions as $session) {
            foreach ($session->clients as $client) {
                $this->deferred->defer(function () use ($session, $client): void {
                    $this->notify($session, $client);
                });
            }
        }
    }

    /**
     * Sign and send one logout token, if the application still wants one. A signing
     * failure is the deferred runner's to log; the other applications are separate tasks.
     *
     * @throws NoActiveSigningKey
     * @throws SigningFailed
     */
    private function notify(Session $session, ClientId $clientId): void
    {
        $client = $this->clients->find($clientId);
        $backChannel = $client?->backChannelLogout;
        if ($client === null || $backChannel === null) {
            return;
        }

        $claims = LogoutTokenClaims::issue(
            $this->issuer,
            $client->id,
            $session->userId,
            $session->sid,
            $this->secrets->token(),
            $this->clock->now(),
            $this->lifetimeSeconds,
        );
        $token = $this->jws->sign($this->signer->activeKey(), $claims->toArray(), LogoutTokenClaims::TYPE);
        $this->delivery->deliver($client->id, $backChannel->uri, $token);
    }
}
