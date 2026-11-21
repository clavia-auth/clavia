<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\ResourceServers;

use Clavia\Application\Management\NotFound;
use Clavia\Domain\ResourceServer\ResourceServer;
use Clavia\Domain\ResourceServer\ResourceServerId;
use Clavia\Domain\ResourceServer\ResourceServerRepository;
use Clavia\Domain\ResourceServer\SystemApiProtected;
use Clavia\Domain\Shared\InvalidValue;

/**
 * `PATCH /api/v1/resource-servers/{resource_server_id}`: rename an API, replace the
 * permissions it defines, turn roles on or off for it, or let first-party applications
 * skip the consent screen for it or not. The identifier never changes —
 * it is the `aud` of every token already issued.
 *
 * A permission dropped from an API stops being issued on the next token, client grants
 * included: they are narrowed to what the API defines at issuance. Every role that
 * granted it stops granting it.
 */
final readonly class UpdateResourceServer
{
    public function __construct(private ResourceServerRepository $resourceServers)
    {
    }

    /**
     * @param string|null                     $name
     * @param list<PermissionDefinition>|null $permissions     The whole new set; null leaves it alone.
     * @param bool|null                       $enforcePolicies Null leaves it alone.
     * @param bool|null                       $allowSkippingConsent Null leaves it alone.
     *
     * @throws NotFound
     * @throws InvalidValue
     * @throws SystemApiProtected When the permissions of a system API would change, its roles be
     *                            turned off, or it would ask for consent.
     */
    public function __invoke(
        ResourceServerId $id,
        ?string $name,
        ?array $permissions,
        ?bool $enforcePolicies = null,
        ?bool $allowSkippingConsent = null,
    ): ResourceServer {
        $resourceServer = $this->resourceServers->find($id) ?? throw NotFound::of('API');

        if ($permissions !== null) {
            $resourceServer = $resourceServer->withPermissions(NewResourceServer::permissions($permissions));
        }
        if ($enforcePolicies !== null) {
            $resourceServer = $resourceServer->enforcingPolicies($enforcePolicies);
        }
        if ($allowSkippingConsent !== null) {
            $resourceServer = $resourceServer->allowingConsentSkip($allowSkippingConsent);
        }
        if ($name !== null) {
            $resourceServer = $resourceServer->renamed($name);
        }
        $this->resourceServers->save($resourceServer);

        return $resourceServer;
    }
}
