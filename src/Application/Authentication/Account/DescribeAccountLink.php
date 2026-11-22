<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\Account;

use Clavia\Application\Port\AccountLinkStore;
use Clavia\Domain\Identity\AccountLinkPurpose;
use Clavia\Domain\Identity\UserRepository;

/**
 * Whether a link may still be followed, for the page it opens on — without spending it.
 */
final readonly class DescribeAccountLink
{
    public function __construct(
        private AccountLinkStore $links,
        private UserRepository $users,
    ) {
    }

    /**
     * @return non-empty-string|null The account's address when the link is good for `$purpose`; null otherwise.
     */
    public function __invoke(#[\SensitiveParameter] ?string $token, AccountLinkPurpose $purpose): ?string
    {
        $link = $token === null || $token === '' ? null : $this->links->find($token);
        if ($link === null || $link->purpose !== $purpose) {
            return null;
        }
        $user = $this->users->find($link->userId);

        return $user !== null && $link->stillMatches($user) ? $user->email : null;
    }
}
