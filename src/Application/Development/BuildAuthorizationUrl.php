<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Development;

use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\OAuth2\CodeChallenge;
use Clavia\Domain\OAuth2\CodeVerifier;
use Clavia\Domain\Shared\RandomSource;
use Clavia\Domain\Shared\ScopeSet;
use Clavia\Domain\Shared\SecretGenerator;

/**
 * Builds a ready-to-open authorization request with a fresh PKCE pair.
 *
 * Generating the `code_verifier`/`code_challenge` pair by hand is the tedious part of
 * trying the flow, so this does it and returns both halves: the parameters of the URL
 * to open, and the verifier needed to redeem the resulting code.
 */
final readonly class BuildAuthorizationUrl
{
    public function __construct(
        private ClientRepository $clients,
        private SecretGenerator $secrets,
        private RandomSource $random,
        private ScopeSet $supportedScopes,
    ) {
    }

    /**
     * @param ClientId|null $clientId The client to authorize as; the seeded development client when null.
     * @param ScopeSet|null $scope    Every scope the server supports when null.
     *
     * @return AuthorizationUrl|null Null when no client was named and none was seeded.
     */
    public function __invoke(?ClientId $clientId, string $redirectUri, ?ScopeSet $scope): ?AuthorizationUrl
    {
        $clientId ??= $this->clients->findByName(SeedDevelopmentData::CLIENT_NAME)?->id;
        if ($clientId === null) {
            return null;
        }

        $verifier = CodeVerifier::generate($this->random);

        return new AuthorizationUrl(
            $clientId,
            $redirectUri,
            $verifier,
            [
                'response_type' => 'code',
                'client_id' => $clientId->value,
                'redirect_uri' => $redirectUri,
                'scope' => ($scope ?? $this->supportedScopes)->toString(),
                'state' => $this->secrets->alphanumeric(22),
                'code_challenge' => CodeChallenge::forVerifier($verifier)->value,
                'code_challenge_method' => CodeChallenge::METHOD,
            ],
        );
    }
}
