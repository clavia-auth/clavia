<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\OAuth2\Consent;

/**
 * What the consent screen shows: who asks, of whom, for what.
 *
 * Every word comes from this server — the application's registered name, the API's
 * definitions — and nothing from the request that led here.
 */
final readonly class ConsentScreen
{
    /**
     * @param string          $clientName  The application's name, or its id when it has none.
     * @param string          $email       Whose account it would act as.
     * @param list<ScopeLine> $oidcScopes  The OpenID Connect scopes asked for.
     * @param list<string>    $formOrigins Where deciding sends the browser on to: the application's
     *                                     redirect origins.
     */
    public function __construct(
        public string $clientName,
        public string $email,
        public array $oidcScopes,
        public ?ConsentedApi $api,
        public array $formOrigins,
    ) {
    }
}
