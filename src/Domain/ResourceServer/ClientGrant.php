<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\ResourceServer;

use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\ScopeSet;
use DateTimeImmutable;

/**
 * Permission for one client to request scopes from one API, as itself — the whole
 * authorization decision of the Client Credentials grant, since no person stands
 * behind the request who could have consented to less.
 *
 * One per client and API: two would be two answers to "may this client ask for this
 * scope", and the more permissive one would always win. Kept apart from anything a
 * client may ask *a user* for, because "holds this outright" and "may ask a person for
 * this" are different statements.
 */
final readonly class ClientGrant
{
    private function __construct(
        public ClientId $clientId,
        public ResourceServerId $resourceServerId,
        public ScopeSet $scopes,
        public DateTimeImmutable $createdAt,
    ) {
    }

    /**
     * Grant `$client` the `$scopes` of `$resourceServer`.
     *
     * Scopes the API does not define are refused, so a typo fails where it is made and
     * not, months later, as a quietly narrower token.
     *
     * @throws InvalidValue When the API does not define one of the scopes.
     */
    public static function grant(
        ClientId $client,
        ResourceServer $resourceServer,
        ScopeSet $scopes,
        DateTimeImmutable $now,
    ): self {
        $undefined = $scopes->without($resourceServer->permissionScopes());
        if (! $undefined->isEmpty()) {
            throw new InvalidValue(sprintf(
                "'%s' does not define: %s.",
                $resourceServer->identifier->value,
                $undefined->toString(),
            ));
        }

        return new self($client, $resourceServer->id, $scopes, $now);
    }

    /**
     * Rebuild a grant from storage. Not checked against the API: a permission the API
     * has since dropped stays recorded here and is ignored by {@see grantableOn()}.
     */
    public static function reconstitute(
        ClientId $client,
        ResourceServerId $resourceServerId,
        ScopeSet $scopes,
        DateTimeImmutable $createdAt,
    ): self {
        return new self($client, $resourceServerId, $scopes, $createdAt);
    }

    /**
     * What the client may ask for now: the granted scopes the API still defines.
     *
     * Intersected rather than trusted, so a permission withdrawn from the API takes
     * effect on the next token instead of leaving stale grants to reconcile by hand.
     *
     * @throws InvalidValue When `$resourceServer` is not the API this grant is on.
     */
    public function grantableOn(ResourceServer $resourceServer): ScopeSet
    {
        if (! $resourceServer->id->equals($this->resourceServerId)) {
            throw new InvalidValue('A client grant is only read against the API it is on.');
        }

        return $this->scopes->intersect($resourceServer->permissionScopes());
    }
}
