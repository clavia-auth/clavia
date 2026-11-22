<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\Passkey;

use Clavia\Domain\Authentication\Passkey\PasskeyRepository;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Identity\UserRepository;

/**
 * What the passkeys page says about an account.
 */
final readonly class DescribePasskeys
{
    /**
     * @param positive-int $maxPerUser `CLAVIA_PASSKEY_MAX_PER_USER`.
     */
    public function __construct(
        private UserRepository $users,
        private PasskeyRepository $passkeys,
        private int $maxPerUser,
    ) {
    }

    /** Null when the account no longer exists. */
    public function __invoke(UserId $userId): ?AccountPasskeys
    {
        $user = $this->users->find($userId);
        if ($user === null) {
            return null;
        }

        return new AccountPasskeys(
            $user->email,
            array_map(DescribedPasskey::of(...), $this->passkeys->ofUser($userId)),
            $this->maxPerUser,
        );
    }
}
