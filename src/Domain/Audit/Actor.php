<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Audit;

use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\Provisioning\ProvisioningTokenId;

/**
 * Who did what an audit event records.
 *
 * A person acting through an application keeps both: the operator *and* the dashboard
 * they used, so an action can be traced to the person and to the credential that carried it. A
 * directory is named by its provisioning token, the credential it holds.
 */
final readonly class Actor
{
    private function __construct(
        public ActorKind $kind,
        public ?UserId $userId,
        public ?ClientId $clientId,
        public ?ProvisioningTokenId $provisioningTokenId = null,
    ) {
    }

    /** A person, on their own or through the application `$via`. */
    public static function person(UserId $userId, ?ClientId $via = null): self
    {
        return new self(ActorKind::Person, $userId, $via);
    }

    /** An application acting as itself. */
    public static function application(ClientId $clientId): self
    {
        return new self(ActorKind::Application, null, $clientId);
    }

    /** A directory, through the provisioning token it holds (SCIM). */
    public static function provisioning(ProvisioningTokenId $token): self
    {
        return new self(ActorKind::Provisioning, null, null, $token);
    }

    public static function system(): self
    {
        return new self(ActorKind::System, null, null);
    }

    /** Somebody, through the application `$via` when one is known. */
    public static function anonymous(?ClientId $via = null): self
    {
        return new self(ActorKind::Anonymous, null, $via);
    }

    /**
     * Read back from storage: the kind and the identifiers it was recorded with.
     */
    public static function reconstitute(
        ActorKind $kind,
        ?UserId $userId,
        ?ClientId $clientId,
        ?ProvisioningTokenId $provisioningTokenId = null,
    ): self {
        return new self($kind, $userId, $clientId, $provisioningTokenId);
    }
}
