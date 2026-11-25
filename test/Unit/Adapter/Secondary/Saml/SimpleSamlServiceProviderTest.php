<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Adapter\Secondary\Saml;

use Clavia\Adapter\Secondary\Saml\SimpleSamlServiceProvider;
use Clavia\Application\Port\Saml\SamlServiceProvider;
use ClaviaTest\Support\Contract\SamlServiceProviderContract;
use PHPUnit\Framework\TestCase;

/**
 * The adapter against genuine XML. No double runs this contract: like the passkey verifier's, it
 * feeds real signatures a double could only pass by being the adapter again (CLAUDE.md, "Known
 * issues"); use cases take {@see \ClaviaTest\Support\Fake\FakeSamlServiceProvider}.
 */
final class SimpleSamlServiceProviderTest extends TestCase
{
    use SamlServiceProviderContract;

    #[\Override]
    protected function samlServiceProvider(): SamlServiceProvider
    {
        return new SimpleSamlServiceProvider();
    }
}
