<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication;

use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\OAuth2\UiLocales;

/**
 * What a page needs to know of the authorization request it serves: the languages it asked for and the
 * application it is for. Nothing more travels from where the request is held to the page.
 */
final readonly class HeldRequest
{
    /**
     * @param UserId|null $askedOf Whom the request was put to, when it is bound to one person (a pending
     *                             consent): what the page shows of its application is for them alone.
     */
    public function __construct(
        public UiLocales $uiLocales,
        public ?ClientId $clientId,
        public ?UserId $askedOf = null,
    ) {
    }

    public static function none(): self
    {
        return new self(UiLocales::none(), null);
    }
}
