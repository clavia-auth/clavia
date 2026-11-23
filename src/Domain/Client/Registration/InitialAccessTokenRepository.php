<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Client\Registration;

use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\Page;
use Clavia\Domain\Shared\PageRequest;
use DateTimeImmutable;

/**
 * The initial access tokens an operator has issued.
 */
interface InitialAccessTokenRepository
{
    public function add(InitialAccessToken $token): void;

    public function find(InitialAccessTokenId $id): ?InitialAccessToken;

    /** Record a revocation. Uses are never written here: {@see spendOne()} owns them. */
    public function save(InitialAccessToken $token): void;

    /**
     * Tokens newest first, searching the description.
     *
     * @return Page<InitialAccessToken>
     */
    public function page(PageRequest $request): Page;

    /**
     * Spend one use of the token with this digest, if it is usable at `$now`, in one conditional
     * write: the answer to "may this caller register a client, and did it win the last use?".
     * Inside the transaction that registers the client, so a registration that fails gives the
     * use back.
     *
     * @return InitialAccessTokenId|null The token spent from; null when there is no such token,
     *                                   or it is revoked, expired or used up.
     */
    #[\NoDiscard]
    public function spendOne(Digest $digest, DateTimeImmutable $now): ?InitialAccessTokenId;
}
