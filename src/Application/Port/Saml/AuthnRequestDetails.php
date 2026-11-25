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
use Clavia\Domain\Shared\Url;
use DateTimeImmutable;

/** One `AuthnRequest` to send (SAML Core §3.4.1). */
final readonly class AuthnRequestDetails
{
    /**
     * @param non-empty-string      $serviceProviderEntityId
     * @param non-empty-string      $relayState The opaque handle of the pending sign-in.
     * @param non-empty-string|null $nameIdFormat The `NameIDPolicy` asked for; none lets the IdP choose.
     */
    public function __construct(
        public Url $singleSignOnUrl,
        public string $serviceProviderEntityId,
        public Url $assertionConsumerServiceUrl,
        public SamlRequestId $id,
        public string $relayState,
        public DateTimeImmutable $issuedAt,
        public ?string $nameIdFormat = null,
    ) {
    }
}
