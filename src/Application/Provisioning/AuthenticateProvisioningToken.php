<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Provisioning;

use Clavia\Application\OAuth2\ClientAuthentication\ClientFailureThrottle;
use Clavia\Application\OAuth2\ClientAuthentication\TooManyFailedRequests;
use Clavia\Domain\Connection\ConnectionRepository;
use Clavia\Domain\Provisioning\ProvisioningTokenRepository;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\Digest;

/**
 * The front door of `/scim/v2` (docs/design/scim-provisioning.md §5.2): which directory is calling,
 * from the provisioning token it presents.
 *
 * A token is a secret, and nobody may probe for one. So, in this order:
 *
 *  1. an address past the limit of failed tokens is refused before any lookup
 *     (`CLAVIA_TOKEN_MAX_FAILURES` within `CLAVIA_TOKEN_FAILURE_WINDOW`, the throttle the machine
 *     endpoints use, by address only);
 *  2. the token is looked up by its digest; unknown, expired or revoked is one refusal, and counts;
 *  3. its connection must still be one a directory may provision, or the token is useless.
 *
 * A usable token is never throttled: a directory's first sync sends thousands of requests.
 */
final readonly class AuthenticateProvisioningToken
{
    public function __construct(
        private ProvisioningTokenRepository $tokens,
        private ConnectionRepository $connections,
        private ClientFailureThrottle $throttle,
        private Clock $clock,
    ) {
    }

    /**
     * Refused before anything is read, when the address has failed too often: also for a request
     * that presents no token at all.
     *
     * @throws TooManyFailedRequests
     */
    public function refuseIfLimited(string $clientAddress): void
    {
        $this->throttle->refuseIfLimited($clientAddress);
    }

    /**
     * @param non-empty-string $secret The token presented.
     *
     * @return ProvisioningCaller|null Null for any token that does not reach `/scim/v2`: one answer.
     *
     * @throws TooManyFailedRequests
     */
    #[\NoDiscard]
    public function __invoke(#[\SensitiveParameter] string $secret, string $clientAddress): ?ProvisioningCaller
    {
        $this->refuseIfLimited($clientAddress);
        $token = $this->tokens->findByDigest(Digest::of($secret));
        if ($token === null || ! $token->isUsableAt($this->clock->now())) {
            $this->throttle->recordFailedAuthentication($clientAddress);

            return null;
        }
        // A genuine token whose connection went away is useless, not a guess: refused, not counted.
        $connection = $this->connections->find($token->connection);
        if ($connection === null || ! $connection->isProvisionable()) {
            return null;
        }

        return new ProvisioningCaller($token, $connection);
    }
}
