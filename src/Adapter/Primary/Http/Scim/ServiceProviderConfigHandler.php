<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Scim;

use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `GET /scim/v2/ServiceProviderConfig` (RFC 7643 §5, RFC 7644 §4): what this service provider
 * supports, as a directory reads it before it sends anything else.
 *
 * It states what exists now, and nothing ahead of it: filtering, PATCH and ETags arrive with the
 * slices that build them (docs/design/scim-provisioning.md §9). Bulk, sorting and password changes
 * are not offered (§1).
 */
final readonly class ServiceProviderConfigHandler implements RequestHandlerInterface
{
    public const string SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig';

    /** The most resources one list answer returns (`count` is capped there). */
    public const int MAX_RESULTS = 200;

    /** @param non-empty-string $baseUrl This service provider's base URL. */
    public function __construct(
        private ScimResponder $responder,
        private string $baseUrl,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        return $this->responder->json([
            'schemas' => [self::SCHEMA],
            'patch' => ['supported' => false],
            'bulk' => ['supported' => false, 'maxOperations' => 0, 'maxPayloadSize' => 0],
            'filter' => ['supported' => false, 'maxResults' => self::MAX_RESULTS],
            'changePassword' => ['supported' => false],
            'sort' => ['supported' => false],
            'etag' => ['supported' => false],
            'authenticationSchemes' => [[
                'type' => 'oauthbearertoken',
                'name' => 'Provisioning token',
                'description' => 'The provisioning token an operator issued for this connection, sent as '
                    . 'Authorization: Bearer.',
                'specUri' => 'https://www.rfc-editor.org/rfc/rfc6750',
                'primary' => true,
            ]],
            'meta' => [
                'resourceType' => 'ServiceProviderConfig',
                'location' => $this->baseUrl . '/ServiceProviderConfig',
            ],
        ]);
    }
}
