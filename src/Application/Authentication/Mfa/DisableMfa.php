<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\Mfa;

use Clavia\Application\Port\DomainEvents;
use Clavia\Application\Port\TransactionManager;
use Clavia\Domain\Authentication\Event\SecondFactorRemoved;
use Clavia\Domain\Authentication\Mfa\MfaFactorRepository;
use Clavia\Domain\Authentication\Mfa\RecoveryCodeRepository;
use Clavia\Domain\Identity\UserId;

/**
 * Turn two-factor authentication off: every factor and every recovery code goes.
 * Idempotent — afterwards it is off, however many times it was asked.
 */
final readonly class DisableMfa
{
    public function __construct(
        private MfaFactorRepository $factors,
        private RecoveryCodeRepository $recoveryCodes,
        private TransactionManager $transactions,
        private DomainEvents $events,
    ) {
    }

    /**
     * @param bool $byTheirOwner False when an operator resets it for them: the request's actor
     *                           is then who did it.
     */
    public function __invoke(UserId $userId, bool $byTheirOwner = true): void
    {
        $this->transactions->transactional(function () use ($userId, $byTheirOwner): void {
            $this->factors->removeAll($userId);
            $this->recoveryCodes->removeAll($userId);
            $this->events->dispatch(new SecondFactorRemoved($userId, $byTheirOwner));
        });
    }
}
