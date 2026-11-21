<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\OAuth2\Device;

use Clavia\Application\OAuth2\Consent\ConsentedApi;
use Clavia\Application\OAuth2\Consent\ScopeLine;

/**
 * What the device page puts to the person: which application asks, for whom, for what.
 */
final readonly class DeviceReview
{
    /**
     * @param list<ScopeLine> $oidcScopes
     */
    public function __construct(
        public string $userCode,
        public string $clientName,
        public string $email,
        public array $oidcScopes,
        public ?ConsentedApi $api,
    ) {
    }
}
