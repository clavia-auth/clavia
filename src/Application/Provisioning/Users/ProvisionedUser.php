<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Provisioning\Users;

use Clavia\Domain\Identity\User;
use Clavia\Domain\Provisioning\ProvisionedAccount;

/** An account a directory provisioned, with what SCIM knows it by: what a `User` resource shows. */
final readonly class ProvisionedUser
{
    public function __construct(
        public User $user,
        public ProvisionedAccount $account,
    ) {
    }

    /**
     * The resource's version (RFC 7644 §3.14): when the account or its record last changed, to the
     * microsecond. What `meta.version`'s weak ETag carries and `If-Match` is compared with.
     *
     * @return non-empty-string
     */
    public function version(): string
    {
        return max($this->user->updatedAt(), $this->account->updatedAt)->format('Uu');
    }

    /**
     * Whether a change conditioned on `If-Match` may go ahead: no condition, `*`, or the current
     * version among those listed.
     *
     * @param list<string>|null $expected The versions the client holds; null when it sent none.
     */
    public function isAt(?array $expected): bool
    {
        return $expected === null || in_array('*', $expected, true) || in_array($this->version(), $expected, true);
    }
}
