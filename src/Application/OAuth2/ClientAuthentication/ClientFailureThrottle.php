<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\OAuth2\ClientAuthentication;

use Clavia\Application\Port\AttemptCounter;
use Clavia\Domain\Client\Client;
use Clavia\Domain\Client\ClientAuthMethod;

/**
 * Limits how many requests may fail at the endpoints machines call — token,
 * introspection, revocation, device authorization — before they are refused for a while.
 *
 * Failures are counted, never successes, so a client that does what it should is never
 * refused, however busy it is. Two subjects:
 *
 * - **the client address**, for every failed client authentication and every rejected
 *   grant. A client secret is 256 random bits and cannot be guessed; what an attacker can
 *   do is make this server run bcrypt on every attempt. The limit is checked before any
 *   secret is, so it caps that work per address.
 * - **the client**, for a rejected grant (a wrong code, verifier, refresh or device code),
 *   and only for a client that proved itself with a secret. A client id is not secret —
 *   a public client's is in every authorization URL — so counting failures under a name
 *   anyone can send would let anyone lock that client out.
 *
 * Every failure restarts the window ({@see AttemptCounter::increment()}): sustained
 * failures stay refused rather than recovering while they go on.
 */
final readonly class ClientFailureThrottle
{
    /**
     * @param positive-int $maxFailures   Failures that trip either subject (`CLAVIA_TOKEN_MAX_FAILURES`).
     * @param positive-int $windowSeconds How long a failure counts (`CLAVIA_TOKEN_FAILURE_WINDOW`).
     */
    public function __construct(
        private AttemptCounter $counter,
        private int $maxFailures,
        private int $windowSeconds,
    ) {
    }

    /**
     * @throws TooManyFailedRequests When the address, or the proven client, has failed too often.
     */
    public function refuseIfLimited(string $clientAddress, ?Client $client = null): void
    {
        foreach (self::subjects($clientAddress, $client) as $subject) {
            if ($this->counter->count($subject) >= $this->maxFailures) {
                throw new TooManyFailedRequests($this->windowSeconds);
            }
        }
    }

    /** A failed client authentication: counted against the address only. */
    public function recordFailedAuthentication(string $clientAddress): void
    {
        $this->counter->increment(self::addressSubject($clientAddress), $this->windowSeconds);
    }

    /** A rejected grant: counted against the address, and against the client if it proved itself. */
    public function recordRejectedGrant(string $clientAddress, Client $client): void
    {
        foreach (self::subjects($clientAddress, $client) as $subject) {
            $this->counter->increment($subject, $this->windowSeconds);
        }
    }

    /**
     * @return list<string>
     */
    private static function subjects(string $clientAddress, ?Client $client): array
    {
        $subjects = [self::addressSubject($clientAddress)];
        if ($client !== null && $client->authMethod !== ClientAuthMethod::None) {
            $subjects[] = 'oauth-client:' . $client->id->value;
        }

        return $subjects;
    }

    private static function addressSubject(string $clientAddress): string
    {
        return 'oauth-address:' . $clientAddress;
    }
}
