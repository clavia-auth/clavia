<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\OAuth2\Device;

/**
 * The device authorization response (RFC 8628 §3.2): what the device polls with, what it
 * shows, where the person goes, and how often it may ask.
 */
final readonly class DeviceAuthorizationStarted
{
    /**
     * @param non-empty-string $deviceCode
     * @param positive-int     $expiresIn
     * @param positive-int     $interval
     */
    public function __construct(
        #[\SensitiveParameter] public string $deviceCode,
        public string $userCode,
        public string $verificationUri,
        public string $verificationUriComplete,
        public int $expiresIn,
        public int $interval,
    ) {
    }
}
