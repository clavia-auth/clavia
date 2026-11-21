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
use Clavia\Domain\Oidc\Event\SigningKeyCreated;
use Clavia\Domain\Oidc\SigningAlgorithm;
use Clavia\Domain\Oidc\SigningKey;
use Clavia\Domain\Shared\Clock;

/**
 * Create the first signing key: `clavia keys:generate`.
 *
 * Refuses when a key is already active. Replacing an active key is a rotation, and a
 * rotation keeps the outgoing key published; "generate" doing it silently would
 * withdraw a key that live tokens still name.
 */
final readonly class GenerateSigningKey
{
    public function __construct(
        private SigningKeyStore $keys,
        private TransactionManager $transactions,
        private Clock $clock,
        private SigningAlgorithm $algorithm,
        private DomainEvents $events,
    ) {
    }

    /**
     * @throws SigningKeyAlreadyActive
     */
    public function __invoke(): SigningKey
    {
        /** @var SigningKey */
        return $this->transactions->transactional(function (): SigningKey {
            $active = $this->keys->lockActive();
            if ($active !== null) {
                throw SigningKeyAlreadyActive::for($active);
            }

            $key = $this->keys->create($this->algorithm, $this->clock->now());
            $this->events->dispatch(new SigningKeyCreated($key));

            return $key;
        });
    }
}
