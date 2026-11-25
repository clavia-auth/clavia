<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\External\Saml;

use Clavia\Application\Port\Saml\ParkedSamlResponse;
use Clavia\Application\Port\Saml\SamlResponseStore;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\SecretGenerator;

/**
 * `POST /auth/saml/{connection}/acs` (docs/design/saml-connections.md §5.3, steps 3 and 4): the identity
 * provider's cross-site POST carries no `SameSite=Lax` cookie, so nothing is decided here. The response
 * and its `RelayState` are kept under a fresh one-time handle for a minute, and the browser is sent on
 * to a GET, where the cookies come back and every check runs. Sizes are bounded and nothing is parsed.
 */
final readonly class ReceiveSamlResponse
{
    /** A response of 256 KiB, in base64. */
    public const int MAX_RESPONSE_LENGTH = 350_000;

    /** A handle is 43 characters; anything far longer is not one. */
    public const int MAX_RELAY_STATE_LENGTH = 80;

    public function __construct(
        private SamlResponseStore $responses,
        private SecretGenerator $secrets,
    ) {
    }

    /** @return non-empty-string|null The handle to complete with; null when the POST is not a response. */
    public function __invoke(
        string $connection,
        #[\SensitiveParameter] ?string $response,
        #[\SensitiveParameter] ?string $relayState,
    ): ?string {
        if (
            $response === null
            || $response === ''
            || strlen($response) > self::MAX_RESPONSE_LENGTH
            || $relayState === null
            || $relayState === ''
            || strlen($relayState) > self::MAX_RELAY_STATE_LENGTH
        ) {
            return null;
        }
        try {
            $name = ConnectionName::fromString($connection);
        } catch (InvalidValue) {
            return null;
        }
        $handle = $this->secrets->token();
        $this->responses->park($handle, new ParkedSamlResponse($name, $response, $relayState));

        return $handle;
    }
}
