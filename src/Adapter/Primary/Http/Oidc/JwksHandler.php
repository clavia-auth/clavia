<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Oidc;

use Clavia\Application\Oidc\Keys\PublishSigningKeys;
use Clavia\Domain\Oidc\PublicJwk;
use Laminas\Diactoros\Response\JsonResponse;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * The JWK Set relying parties verify this server's tokens with (RFC 7517 §5), at the
 * `jwks_uri`.
 *
 * Cacheable for {@see PublishSigningKeys::CACHE_MAX_AGE}, the number key rotation is
 * designed around. Rendered from stored public keys only.
 */
final readonly class JwksHandler implements RequestHandlerInterface
{
    public function __construct(private PublishSigningKeys $publish)
    {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $keys = array_map(static fn (PublicJwk $key): array => $key->toArray(), ($this->publish)());

        return new JsonResponse(
            ['keys' => $keys],
            200,
            ['Cache-Control' => sprintf('public, max-age=%d', PublishSigningKeys::CACHE_MAX_AGE)],
        );
    }
}
