<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\ProvisioningTokens;

use Clavia\Application\Management\NotFound;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Provisioning\ProvisioningToken;
use Clavia\Domain\Provisioning\ProvisioningTokenId;
use Clavia\Domain\Provisioning\ProvisioningTokenRepository;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\Page;
use Clavia\Domain\Shared\PageRequest;
use DateTimeImmutable;

/**
 * `GET /api/v1/provisioning-tokens` and `GET …/{id}`: the tokens issued, newest first. Never their
 * secrets, which are not kept.
 */
final readonly class ReadProvisioningTokens
{
    public function __construct(
        private ProvisioningTokenRepository $tokens,
        private Clock $clock,
    ) {
    }

    /**
     * @param string|null $connection Only that connection's tokens; an unknown one has none.
     *
     * @return Page<ProvisioningToken>
     */
    public function page(PageRequest $request, ?string $connection = null): Page
    {
        if ($connection === null) {
            return $this->tokens->page($request);
        }
        try {
            $name = ConnectionName::fromString($connection);
        } catch (InvalidValue) {
            /** @var Page<ProvisioningToken> */
            return new Page([], 0, $request);
        }

        return $this->tokens->page($request, $name);
    }

    /**
     * @throws NotFound
     */
    public function find(ProvisioningTokenId $id): ProvisioningToken
    {
        return $this->tokens->find($id) ?? throw NotFound::of('provisioning token');
    }

    /** The instant a token's state is told at: now. */
    public function now(): DateTimeImmutable
    {
        return $this->clock->now();
    }
}
