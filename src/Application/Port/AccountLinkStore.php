<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Port;

use Clavia\Domain\Identity\AccountLink;

/**
 * Links emailed to accounts ({@see AccountLink}), waiting to be followed, keyed by the
 * link's secret token and stored as its digest: reading the store yields no working link.
 */
interface AccountLinkStore
{
    /**
     * @param non-empty-string $token
     * @param positive-int     $lifetimeSeconds Never extended afterwards.
     */
    public function open(#[\SensitiveParameter] string $token, AccountLink $link, int $lifetimeSeconds): void;

    /** The link, without spending it: what a page shows before the person confirms. */
    public function find(#[\SensitiveParameter] string $token): ?AccountLink;

    /**
     * Take the link out of the store: of two requests presenting the same token, one gets it
     * and the other null — a link works once.
     */
    public function claim(#[\SensitiveParameter] string $token): ?AccountLink;
}
