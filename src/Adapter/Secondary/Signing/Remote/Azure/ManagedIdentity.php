<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Signing\Remote\Azure;

use Clavia\Adapter\Secondary\Signing\Remote\AccessTokens;
use Clavia\Adapter\Secondary\Signing\Remote\IssuedToken;
use Clavia\Adapter\Secondary\Signing\Remote\JsonApi;
use Clavia\Domain\Shared\Clock;

/**
 * Tokens from the managed identity of the Azure host this server runs on — nothing secret
 * is configured, which is why it is the default.
 *
 * Two endpoints serve them: the Instance Metadata Service on virtual machines, scale sets
 * and AKS nodes, and the one App Service, Functions and Container Apps announce in
 * `IDENTITY_ENDPOINT` with the `IDENTITY_HEADER` that proves the caller is local. A
 * client id selects a user-assigned identity; without one, the system-assigned identity
 * answers.
 */
final class ManagedIdentity implements AccessTokens
{
    public const string INSTANCE_METADATA = 'http://169.254.169.254/metadata/identity/oauth2/token';

    private const string SERVICE = 'The Azure managed identity endpoint';

    private ?IssuedToken $current = null;

    /**
     * @param string      $scope    The `…/.default` scope of the service the token is for.
     * @param string|null $endpoint `IDENTITY_ENDPOINT`, on a host that sets it.
     * @param string|null $header   `IDENTITY_HEADER`, which comes with it.
     */
    public function __construct(
        private readonly JsonApi $api,
        private readonly Clock $clock,
        private readonly string $scope,
        private readonly ?string $clientId = null,
        private readonly ?string $endpoint = null,
        #[\SensitiveParameter] private readonly ?string $header = null,
    ) {
    }

    #[\Override]
    public function token(): string
    {
        $now = $this->clock->now();
        if ($this->current?->isUsableAt($now) !== true) {
            $this->current = IssuedToken::fromResponse($this->request(), $now, self::SERVICE);
        }

        return $this->current->token;
    }

    /**
     * @return array<array-key, mixed>
     */
    private function request(): array
    {
        // Both endpoints want the resource, not the scope: the scope without `/.default`.
        $query = ['resource' => preg_replace('/\/\.default$/D', '', $this->scope) ?? $this->scope];
        if ($this->clientId !== null) {
            $query['client_id'] = $this->clientId;
        }

        if ($this->endpoint !== null && $this->header !== null) {
            return $this->api->get(
                $this->endpoint . '?' . http_build_query(['api-version' => '2019-08-01'] + $query),
                ['X-IDENTITY-HEADER' => $this->header],
            );
        }

        return $this->api->get(
            self::INSTANCE_METADATA . '?' . http_build_query(['api-version' => '2018-02-01'] + $query),
            ['Metadata' => 'true'],
        );
    }
}
