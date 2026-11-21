<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Consent;

use Clavia\Domain\Client\Client;
use Clavia\Domain\OAuth2\Prompt;
use Clavia\Domain\ResourceServer\ResourceServer;
use Clavia\Domain\Shared\ScopeSet;

/**
 * Whether an authorization request has to be put to the person on the consent screen.
 *
 * In the order it is decided:
 *
 * 1. `prompt=consent` asks: the client wants the screen shown, whatever came before.
 * 2. A **first-party** application does not ask when the request names no API — the
 *    operator runs it, and signing in is the consent — or names one that lets first-party
 *    applications skip consent ({@see ResourceServer::$allowSkippingConsent}).
 * 3. Otherwise — a **third-party** application always, a first-party one on an API that
 *    insists — it asks unless the person already agreed to every scope requested, for this
 *    application on this API.
 *
 * Third-party applications never reach a system API at all; that refusal comes before
 * consent is considered.
 */
final class ConsentPolicy
{
    private function __construct()
    {
    }

    /**
     * @param ResourceServer|null $api   The API named in `audience`, if any.
     * @param ScopeSet            $scope What the request asks for.
     * @param UserConsent|null    $given What the person agreed to before, for this application and API.
     */
    public static function mustAsk(
        Client $client,
        ?ResourceServer $api,
        Prompt $prompt,
        ScopeSet $scope,
        ?UserConsent $given,
    ): bool {
        if ($prompt->demandsConsent()) {
            return true;
        }

        if ($client->isFirstParty() && ($api === null || $api->allowSkippingConsent)) {
            return false;
        }

        return $given === null || ! $given->covers($scope);
    }
}
