<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Port\Saml;

use Clavia\Domain\Connection\Saml\SamlRequestId;
use DateTimeImmutable;

/** What a response must be, for one connection and one request. */
final readonly class ExpectedResponse
{
    /**
     * @param non-empty-string           $identityProviderEntityId The `Issuer` it must name.
     * @param non-empty-list<non-empty-string> $certificates PEM; only these verify, compared by key.
     * @param non-empty-string           $serviceProviderEntityId The `Audience` it must name.
     * @param non-empty-string           $assertionConsumerServiceUrl The `Destination` and `Recipient`.
     * @param non-empty-string|null      $subjectAttribute The attribute that names the person; the
     *     persistent `NameID` when null.
     * @param ContentKeyDecrypter|null   $decrypter This server's encryption keys; null when it has none, and
     *     an encrypted assertion cannot be read.
     * @param bool                       $requireEncryption A plain assertion is refused.
     * @param bool                       $requireGcm An assertion encrypted with AES-CBC is refused.
     */
    public function __construct(
        public string $identityProviderEntityId,
        public array $certificates,
        public string $serviceProviderEntityId,
        public string $assertionConsumerServiceUrl,
        public SamlRequestId $inResponseTo,
        public DateTimeImmutable $now,
        public ?string $subjectAttribute = null,
        public ?ContentKeyDecrypter $decrypter = null,
        public bool $requireEncryption = false,
        public bool $requireGcm = false,
    ) {
    }
}
