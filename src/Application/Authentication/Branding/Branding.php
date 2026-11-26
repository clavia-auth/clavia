<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\Branding;

use Clavia\Domain\Client\AccentColor;
use Clavia\Domain\Client\ClientId;

/**
 * How the sign-in pages of a request for this application look (#25): its name, its colour and its logo,
 * each by what a page names it.
 */
final readonly class Branding
{
    /**
     * @param non-empty-string|null $logoVersion What the page names the logo by; null when it has none.
     */
    public function __construct(
        public ClientId $clientId,
        public string $name,
        public ?AccentColor $accentColor,
        public ?string $logoVersion,
    ) {
    }
}
