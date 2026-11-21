<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use GuzzleHttp\Client;
use GuzzleHttp\RequestOptions;
use Psr\Container\ContainerInterface;
use Psr\Http\Client\ClientInterface;

/**
 * The PSR-18 client the signing services are called with: Google Cloud KMS, Azure Key
 * Vault and the endpoints that issue their tokens.
 *
 * Not {@see HttpClientFactory}'s: that one refuses private and link-local addresses,
 * because it fetches URLs anybody registering an application may type in, and the Azure
 * managed identity endpoint *is* link-local (`169.254.169.254`). Every address this one
 * reaches comes from the operator's own signing configuration. Bounded and without
 * redirects all the same.
 */
final class SigningHttpClientFactory
{
    public const string SERVICE = 'clavia.http.signing';

    public const float CONNECT_TIMEOUT = 5.0;

    public const float TIMEOUT = 10.0;

    public function __invoke(ContainerInterface $container): ClientInterface
    {
        return new Client([
            RequestOptions::CONNECT_TIMEOUT => self::CONNECT_TIMEOUT,
            RequestOptions::TIMEOUT => self::TIMEOUT,
            RequestOptions::ALLOW_REDIRECTS => false,
            RequestOptions::HTTP_ERRORS => false,
        ]);
    }
}
