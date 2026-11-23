<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\InitialAccessTokens;

use Clavia\Domain\Client\Registration\InitialAccessToken;
use Clavia\Domain\Client\Registration\InitialAccessTokenRepository;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\Page;
use Clavia\Domain\Shared\PageRequest;
use DateTimeImmutable;

/**
 * `GET /api/v1/initial-access-tokens`: the tokens issued, newest first. Never their secrets,
 * which are not kept.
 */
final readonly class ReadInitialAccessTokens
{
    public function __construct(
        private InitialAccessTokenRepository $tokens,
        private Clock $clock,
    ) {
    }

    /**
     * @return Page<InitialAccessToken>
     */
    public function page(PageRequest $request): Page
    {
        return $this->tokens->page($request);
    }

    /** The instant a token's state is told at: now. */
    public function now(): DateTimeImmutable
    {
        return $this->clock->now();
    }
}
