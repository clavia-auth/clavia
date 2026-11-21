<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Users;

use Clavia\Domain\Client\Client;
use Clavia\Domain\Consent\UserConsent;
use Clavia\Domain\Shared\Audience;

/**
 * A consent, with the application and the API it names as they are now.
 */
final readonly class DescribedConsent
{
    /**
     * @param Audience|null $audience The identifier of the API it is for; null for a request that named none.
     */
    public function __construct(
        public UserConsent $consent,
        public Client $client,
        public ?Audience $audience,
    ) {
    }
}
