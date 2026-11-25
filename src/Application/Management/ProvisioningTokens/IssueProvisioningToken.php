<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\ProvisioningTokens;

use Clavia\Application\Port\DomainEvents;
use Clavia\Domain\Connection\ConnectionName;
use Clavia\Domain\Connection\ConnectionRepository;
use Clavia\Domain\Provisioning\Event\ProvisioningTokenIssued;
use Clavia\Domain\Provisioning\ProvisioningToken;
use Clavia\Domain\Provisioning\ProvisioningTokenId;
use Clavia\Domain\Provisioning\ProvisioningTokenRepository;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\RandomSource;
use Clavia\Domain\Shared\SecretGenerator;

/**
 * `POST /api/v1/provisioning-tokens`: issue a token a directory reaches `/scim/v2` with, for one
 * connection (docs/design/scim-provisioning.md §5.1). The secret is returned once and stored as its
 * digest.
 */
final readonly class IssueProvisioningToken
{
    public function __construct(
        private ProvisioningTokenRepository $tokens,
        private ConnectionRepository $connections,
        private SecretGenerator $secrets,
        private RandomSource $random,
        private Clock $clock,
        private DomainEvents $events,
    ) {
    }

    /**
     * @throws InvalidValue When the connection is unknown or not provisionable, or the description or
     *                      the lifetime is out of bounds.
     */
    public function __invoke(NewProvisioningToken $new): IssuedProvisioningToken
    {
        try {
            $connection = $this->connections->find(ConnectionName::fromString($new->connection));
        } catch (InvalidValue) {
            $connection = null;
        }
        if ($connection === null || ! $connection->isProvisionable()) {
            // The same answer either way, and never the name: a directory provisions a pool or an
            // enterprise connection (OpenID Connect, SAML), never a social or passwordless one.
            throw new InvalidValue('A provisioning token is for an existing pool, OIDC or SAML connection.');
        }
        $secret = $this->secrets->token();
        $token = ProvisioningToken::issue(
            ProvisioningTokenId::generate($this->random),
            Digest::of($secret),
            $connection->name,
            $new->description,
            $this->clock->now(),
            $new->lifetimeSeconds,
            $new->subjectAttribute,
            $new->addressesTrusted,
            $new->deleteDeactivates,
        );
        $this->tokens->add($token);
        $this->events->dispatch(new ProvisioningTokenIssued($token));

        return new IssuedProvisioningToken($token, $secret);
    }
}
