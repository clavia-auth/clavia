<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\ProvisioningTokens;

use Clavia\Application\Management\NotFound;
use Clavia\Application\Port\DomainEvents;
use Clavia\Domain\Provisioning\Event\ProvisioningTokenRevoked;
use Clavia\Domain\Provisioning\ProvisioningTokenId;
use Clavia\Domain\Provisioning\ProvisioningTokenRepository;
use Clavia\Domain\Shared\Clock;

/**
 * `DELETE /api/v1/provisioning-tokens/{id}`: stop a token at once. The accounts it provisioned stay;
 * revoking it again changes nothing, and records nothing.
 */
final readonly class RevokeProvisioningToken
{
    public function __construct(
        private ProvisioningTokenRepository $tokens,
        private Clock $clock,
        private DomainEvents $events,
    ) {
    }

    /**
     * @throws NotFound
     */
    public function __invoke(ProvisioningTokenId $id): void
    {
        $token = $this->tokens->find($id) ?? throw NotFound::of('provisioning token');
        if ($token->revokedAt !== null) {
            return;
        }

        $revoked = $token->revoke($this->clock->now());
        $this->tokens->save($revoked);
        $this->events->dispatch(new ProvisioningTokenRevoked($revoked));
    }
}
