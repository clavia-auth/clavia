<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Port;

use Clavia\Domain\OAuth2\DeviceAuthorization;
use Clavia\Domain\OAuth2\UserCode;
use Clavia\Domain\Shared\Digest;

/**
 * Where device authorizations wait (RFC 8628), for their short life and the grace after:
 * short-TTL material, Redis's by the storage split.
 *
 * Found by either code: the device's, by its digest — the code itself is never stored —
 * and the user code a person types.
 */
interface DeviceAuthorizationStore
{
    /**
     * Keep a new request for its retention.
     *
     * @return bool False, storing nothing, when its user code stands for a live request
     *              already: the caller draws another.
     */
    public function open(DeviceAuthorization $authorization): bool;

    public function findByDeviceCode(Digest $deviceCode): ?DeviceAuthorization;

    public function findByUserCode(UserCode $userCode): ?DeviceAuthorization;

    /** Store the changes to a request still kept — a poll, a decision. Its retention stays. */
    public function save(DeviceAuthorization $authorization): void;

    /**
     * Forget the request, once its tokens are issued.
     *
     * @return bool Whether this call forgot it: of two concurrent redemptions, only one
     *              may issue tokens.
     */
    public function consume(DeviceAuthorization $authorization): bool;
}
