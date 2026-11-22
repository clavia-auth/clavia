<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\Passkey;

/**
 * The passkeys page of an account: whose it is, its passkeys, and whether it may add another.
 */
final readonly class AccountPasskeys
{
    /**
     * @param list<DescribedPasskey> $passkeys Oldest first.
     * @param positive-int           $limit
     */
    public function __construct(
        public string $email,
        public array $passkeys,
        public int $limit,
    ) {
    }

    public function canAddAnother(): bool
    {
        return count($this->passkeys) < $this->limit;
    }
}
