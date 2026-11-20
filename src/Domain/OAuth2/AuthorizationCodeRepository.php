<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\OAuth2;

use Clavia\Domain\Shared\Digest;

/**
 * Where authorization codes are kept — in durable storage, not in a cache, however
 * short-lived they are: single use needs a row that can be locked, and replay detection
 * needs the spent row to outlive the code.
 */
interface AuthorizationCodeRepository
{
    public function add(AuthorizationCode $code): void;

    /**
     * Find a code by its digest and hold it against every other caller until the
     * surrounding transaction ends.
     *
     * Must be called inside {@see \Clavia\Application\Port\TransactionManager::transactional()}:
     * a concurrent redemption of the same code waits here, and then sees whatever this
     * one decided.
     */
    public function lockForRedemption(Digest $digest): ?AuthorizationCode;

    /** Persist the state of a code that {@see AuthorizationCode::redeem()} just spent. */
    public function save(AuthorizationCode $code): void;
}
