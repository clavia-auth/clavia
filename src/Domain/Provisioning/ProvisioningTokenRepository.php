<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Provisioning;

use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\Page;
use Clavia\Domain\Shared\PageRequest;

/**
 * The provisioning tokens an operator has issued. Deleting a connection deletes its tokens.
 */
interface ProvisioningTokenRepository
{
    public function add(ProvisioningToken $token): void;

    public function find(ProvisioningTokenId $id): ?ProvisioningToken;

    /** The token whose secret has this digest, whatever its state. */
    public function findByDigest(Digest $digest): ?ProvisioningToken;

    /** Record a revocation: nothing else of a token ever changes. */
    public function save(ProvisioningToken $token): void;

    /**
     * Tokens newest first, searching the description, those of one connection when it is named.
     *
     * @return Page<ProvisioningToken>
     */
    public function page(PageRequest $request, ?ConnectionName $connection = null): Page;
}
