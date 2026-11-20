<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Identity;

use Clavia\Domain\Shared\AlreadyExists;

/**
 * Identities linked to accounts, keyed `(provider, subject)`.
 */
interface ExternalIdentityRepository
{
    /** The identity the provider's subject is linked as, if any. */
    public function find(ProviderName $provider, string $subject): ?ExternalIdentity;

    /**
     * @throws AlreadyExists When the provider's subject is already linked — to this account or
     *                       another: a subject belongs to one account.
     */
    public function add(ExternalIdentity $identity): void;
}
