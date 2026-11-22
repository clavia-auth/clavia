<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Adapter\Secondary\WebAuthn;

use Clavia\Application\Port\PasskeyVerifier;
use Clavia\Bootstrap\Container\PasskeyVerifierFactory;
use ClaviaTest\Support\Contract\PasskeyVerifierContract;
use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface;

/**
 * The verifier on `web-auth/webauthn-lib`, against genuine responses made by a software
 * authenticator with real keys. It does no I/O: verifying a response is arithmetic.
 *
 * There is no in-memory double that runs this contract: one that did would be the adapter again,
 * since only real CBOR, COSE and signatures can make the responses the contract feeds it. Use
 * cases are tested with `FakePasskeyVerifier`, which is told what to answer.
 */
final class WebAuthnLibPasskeyVerifierTest extends TestCase
{
    use PasskeyVerifierContract;

    #[\Override]
    protected function verifier(): PasskeyVerifier
    {
        return new PasskeyVerifierFactory()(new class implements ContainerInterface {
            #[\Override]
            public function get(string $id): mixed
            {
                throw new \LogicException('The verifier needs nothing from the container.');
            }

            #[\Override]
            public function has(string $id): bool
            {
                return false;
            }
        });
    }
}
