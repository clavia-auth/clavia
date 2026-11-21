<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Oidc\Keys;

use Clavia\Application\Port\DomainEvents;
use Clavia\Application\Port\SigningKeyStore;
use Clavia\Application\Port\TransactionManager;
use Clavia\Domain\Oidc\Event\SigningKeyRotated;
use Clavia\Domain\Oidc\SigningAlgorithm;
use Clavia\Domain\Shared\Clock;

/**
 * Replace the active signing key: `clavia keys:rotate`.
 *
 * The new key signs from the moment the transaction commits; the outgoing one stops
 * signing at the same moment and stays in the JWKS for the grace period, so every token
 * it signed keeps verifying until it expires. Both keys are published together, so a
 * relying party that refetches the JWKS on an unknown `kid` (OIDC Core §10.1.1) finds
 * the new one straight away.
 *
 * The active key is locked first: two rotations at once cannot both retire it, and the
 * database refuses a second active key besides.
 */
final readonly class RotateSigningKey
{
    /**
     * @param positive-int $graceSeconds How long the outgoing key stays published: {@see self::grace()}.
     */
    public function __construct(
        private SigningKeyStore $keys,
        private TransactionManager $transactions,
        private Clock $clock,
        private SigningAlgorithm $algorithm,
        private int $graceSeconds,
        private DomainEvents $events,
    ) {
    }

    /**
     * How long a retired key stays published: twice the longest lifetime of anything
     * the server signs, for clock skew between it and relying parties, plus a day for
     * JWKS documents cached along the way and for ID tokens presented again later as an
     * `id_token_hint`.
     *
     * @param positive-int $longestTokenLifetime Seconds.
     *
     * @return positive-int Seconds.
     */
    public static function grace(int $longestTokenLifetime): int
    {
        return $longestTokenLifetime * 2 + 86_400;
    }

    public function __invoke(): Rotation
    {
        /** @var Rotation */
        return $this->transactions->transactional(function (): Rotation {
            $now = $this->clock->now();

            $outgoing = $this->keys->lockActive();
            if ($outgoing !== null) {
                $outgoing->retire($now, $this->graceSeconds);
                $this->keys->save($outgoing);
            }

            $incoming = $this->keys->create($this->algorithm, $now);
            $this->events->dispatch(new SigningKeyRotated($incoming, $outgoing));

            return new Rotation($incoming, $outgoing);
        });
    }
}
