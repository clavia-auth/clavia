<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Primary\Http\Auth\Saml;

use Clavia\Adapter\Primary\Http\Shared\ErrorResponder;
use Clavia\Application\Connection\Saml\DescribeSamlServiceProvider;
use Fig\Http\Message\StatusCodeInterface;
use Laminas\Diactoros\Response;
use Laminas\Diactoros\StreamFactory;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * `GET /auth/saml/{connection}/metadata` (docs/design/saml-connections.md §5.4): what an identity
 * provider's administrator is given, as `application/samlmetadata+xml` (the media type
 * SAML Metadata §4.1.1 registers), public and cached for an hour: nothing secret in it, and identity
 * providers that poll it read the next certificate well before it is used. An unknown or disabled
 * connection is a plain `404`.
 */
final readonly class SamlMetadataHandler implements RequestHandlerInterface
{
    public const int CACHE_MAX_AGE = 3600;

    public function __construct(
        private DescribeSamlServiceProvider $describe,
        private ErrorResponder $errors,
    ) {
    }

    #[\Override]
    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        /** @var mixed $name */
        $name = $request->getAttribute('connection');
        $metadata = is_string($name) ? ($this->describe)($name) : null;
        if ($metadata === null) {
            return $this->errors->notFound($request);
        }

        return new Response(
            (new StreamFactory())->createStream($metadata),
            StatusCodeInterface::STATUS_OK,
            [
                'Content-Type' => 'application/samlmetadata+xml',
                'Cache-Control' => sprintf('public, max-age=%d', self::CACHE_MAX_AGE),
                'X-Content-Type-Options' => 'nosniff',
            ],
        );
    }
}
