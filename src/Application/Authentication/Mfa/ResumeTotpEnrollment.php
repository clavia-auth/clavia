<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\Mfa;

use Clavia\Domain\Authentication\Mfa\MfaFactorRepository;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Identity\UserRepository;

/**
 * The pending enrollment again — after a mistyped code — so the seed already in the
 * person's app stays the right one rather than being replaced.
 */
final readonly class ResumeTotpEnrollment
{
    public function __construct(
        private UserRepository $users,
        private MfaFactorRepository $factors,
        private TotpSeeds $seeds,
    ) {
    }

    /** Null when there is no pending factor (none, or already confirmed). */
    public function __invoke(UserId $userId): ?TotpEnrollment
    {
        $user = $this->users->find($userId);
        $factor = $this->factors->find($userId);
        if ($user === null || $factor === null || $factor->isConfirmed()) {
            return null;
        }

        return $this->seeds->enrollment($this->seeds->open($factor), $user->email);
    }
}
