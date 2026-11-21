<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Audit;

use Clavia\Domain\Audit\Actor;

/**
 * Where the request being handled came from, and — once its credentials are known — who
 * is behind it: what every audit event of the request is stamped with, without each use
 * case having to be told.
 *
 * One per request. The HTTP pipeline sets the origin before anything else runs and the
 * Management API's authentication names the caller; at the console both stay unset, and
 * the actor is the operator running the command ({@see Actor::system()}).
 */
final class AuditContext
{
    private ?string $clientAddress = null;

    private ?string $userAgent = null;

    private ?Actor $actor = null;

    /** A new request: its origin, and nobody known yet. */
    public function begin(?string $clientAddress, ?string $userAgent): void
    {
        $this->clientAddress = $clientAddress;
        $this->userAgent = $userAgent;
        $this->actor = null;
    }

    /** Who the request's credentials say is acting. */
    public function actAs(Actor $actor): void
    {
        $this->actor = $actor;
    }

    public function clientAddress(): ?string
    {
        return $this->clientAddress;
    }

    public function userAgent(): ?string
    {
        return $this->userAgent;
    }

    /** The actor named for this request; null when none was. */
    public function actor(): ?Actor
    {
        return $this->actor;
    }
}
