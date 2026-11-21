<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\OAuth2\Consent;

use Clavia\Application\Authentication\EndUser;
use Clavia\Domain\Shared\ScopeSet;

/**
 * `GET /auth/consent`: what the screen shows for a request on hold.
 *
 * Only what means something is shown: an OpenID Connect scope this server supports, or a
 * permission the named API defines. Anything else was refused at the authorization
 * endpoint and never reaches here.
 */
final readonly class DescribeConsent
{
    /**
     * @param ScopeSet $supportedScopes The OIDC scopes this server issues.
     */
    public function __construct(
        private HeldConsents $held,
        private ScopeSet $supportedScopes,
    ) {
    }

    /**
     * @return ConsentScreen|null Null when the handle stands for nothing the signed-in person may decide.
     */
    public function __invoke(#[\SensitiveParameter] string $handle, EndUser $endUser): ?ConsentScreen
    {
        $held = $this->held->find($handle, $endUser);
        if ($held === null) {
            return null;
        }

        $pending = $held->pending;

        return new ConsentScreen(
            $held->client->name === '' ? $held->client->id->value : $held->client->name,
            $held->user->email,
            ScopeDescriptions::oidc($pending->scope, $this->supportedScopes),
            $held->api === null ? null : ScopeDescriptions::api($held->api, $pending->scope),
            $held->client->redirectOrigins(),
        );
    }
}
