<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Domain\OAuth2\AuthorizationCode;
use Clavia\Domain\OAuth2\AuthorizationCodeRepository;
use Clavia\Domain\Shared\Digest;
use LogicException;

/**
 * Authorization codes kept in an array. Stores and returns copies, so a code spent in
 * memory is not spent "in storage" until it is saved — as with the real thing.
 */
final class InMemoryAuthorizationCodeRepository implements AuthorizationCodeRepository
{
    /** @var array<string, AuthorizationCode> Keyed by digest. */
    private array $codes = [];

    /**
     * @param InMemoryTransactionManager|null $transactions When given, locking outside a transaction is
     *                                                      refused, as the real repository does.
     */
    public function __construct(private readonly ?InMemoryTransactionManager $transactions = null)
    {
    }

    #[\Override]
    public function add(AuthorizationCode $code): void
    {
        $this->codes[$code->digest->toString()] = clone $code;
    }

    #[\Override]
    public function lockForRedemption(Digest $digest): ?AuthorizationCode
    {
        if ($this->transactions !== null && ! $this->transactions->isActive()) {
            throw new LogicException('An authorization code can only be locked inside a transaction.');
        }

        return isset($this->codes[$digest->toString()]) ? clone $this->codes[$digest->toString()] : null;
    }

    #[\Override]
    public function save(AuthorizationCode $code): void
    {
        $this->codes[$code->digest->toString()] = clone $code;
    }

    /**
     * @return list<AuthorizationCode> Everything stored, for assertions.
     */
    public function all(): array
    {
        return array_values($this->codes);
    }
}
