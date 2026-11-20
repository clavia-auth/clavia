<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Oidc;

use Clavia\Application\Oidc\Discovery\ProviderMetadata;
use Laminas\Diactoros\Response\JsonResponse;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * The provider's metadata, at both well-known locations: `/.well-known/openid-configuration`
 * for OpenID relying parties (Discovery 1.0 §4) and `/.well-known/oauth-authorization-server`
 * for OAuth clients (RFC 8414 §3). One document, so the two cannot disagree.
 *
 * Public and cacheable: it changes only with a deployment.
 */
final readonly class DiscoveryHandler implements RequestHandlerInterface
{
    /** How long a client may cache the document, in seconds. */
    public const int CACHE_MAX_AGE = 3600;

    public function __construct(private ProviderMetadata $metadata)
    {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        return new JsonResponse(
            $this->metadata->toArray(),
            200,
            ['Cache-Control' => sprintf('public, max-age=%d', self::CACHE_MAX_AGE)],
            JsonResponse::DEFAULT_JSON_FLAGS | JSON_UNESCAPED_SLASHES,
        );
    }
}
