<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Bootstrap\Container;

use Clavia\Adapter\Secondary\WebAuthn\WebAuthnLibPasskeyVerifier;
use Clavia\Application\Port\PasskeyVerifier;
use Psr\Container\ContainerInterface;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AttestationStatement\NoneAttestationStatementSupport;
use Webauthn\Denormalizer\WebauthnSerializerFactory;

/**
 * The verifier, reading responses with the library's own serializer. Attestation is `none`, so
 * `none` is the only attestation format it knows: a credential that arrives with another is
 * refused rather than half-trusted.
 */
final class PasskeyVerifierFactory
{
    public function __invoke(ContainerInterface $container): PasskeyVerifier
    {
        return new WebAuthnLibPasskeyVerifier(
            new WebauthnSerializerFactory(
                new AttestationStatementSupportManager([new NoneAttestationStatementSupport()]),
            )->create(),
        );
    }
}
