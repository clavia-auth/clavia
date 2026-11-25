<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Port\Saml;

/** This server, as one connection's service provider, for its metadata. */
final readonly class ServiceProviderDescription
{
    /**
     * @param non-empty-string      $entityId
     * @param non-empty-string      $assertionConsumerServiceUrl
     * @param non-empty-string|null $nameIdFormat
     * @param list<non-empty-string> $signingCertificates DER, base64: this server's keys (slice 2).
     * @param list<non-empty-string> $encryptionCertificates DER, base64.
     * @param bool                   $signsRequests Whether this connection signs its `AuthnRequest`s, which it
     *                                              can only with a signing certificate.
     */
    public function __construct(
        public string $entityId,
        public string $assertionConsumerServiceUrl,
        public ?string $nameIdFormat = null,
        public array $signingCertificates = [],
        public array $encryptionCertificates = [],
        public bool $signsRequests = true,
    ) {
    }
}
