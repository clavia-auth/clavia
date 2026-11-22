<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Authentication\Event;

use Clavia\Domain\Authentication\AuthenticationMethod;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Shared\DomainEvent;

/**
 * A sign-in attempt failed — the person was refused, not the request malformed.
 *
 * Whoever tried is not known to be the account's owner, so nothing here names them as
 * such: `$userId` is the account the attempt was against, when one could be told.
 */
final readonly class SignInRefused implements DomainEvent
{
    /**
     * @param AuthenticationMethod|null $method The factor that was refused; null when it cannot be told, as
     *                                          for a passkey Clavia does not know.
     * @param UserId|null          $userId     The account aimed at, when exactly one could be told.
     * @param string|null          $email      The address typed, as typed; never a password or a code.
     * @param ClientId|null        $clientId   The application the sign-in was for, if any.
     * @param ConnectionName|null  $connection The connection the attempt went through, when it is not the pool.
     */
    public function __construct(
        public ?AuthenticationMethod $method,
        public SignInRefusal $reason,
        public ?UserId $userId = null,
        public ?string $email = null,
        public ?ClientId $clientId = null,
        public ?ConnectionName $connection = null,
    ) {
    }
}
