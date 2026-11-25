<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Contract;

use Clavia\Application\Port\Saml\ParkedSamlResponse;
use Clavia\Application\Port\Saml\SamlAssertionReplayCache;
use Clavia\Application\Port\Saml\SamlResponseStore;
use Clavia\Domain\Connection\ConnectionName;
use PHPUnit\Framework\Attributes\Test;

/** The SAML sign-in's one-time stores, the doubles and Redis alike. */
trait SamlStoresContract
{
    abstract protected function samlResponses(): SamlResponseStore;

    abstract protected function samlAssertions(): SamlAssertionReplayCache;

    #[Test]
    public function aParkedResponseIsClaimedOnce(): void
    {
        $parked = new ParkedSamlResponse(ConnectionName::fromString('acme'), 'PHNhbWxwOlJlc3BvbnNlLz4=', 'relay');
        $this->samlResponses()->park('handle-1', $parked);

        self::assertEquals($parked, $this->samlResponses()->claim('handle-1'));
        self::assertNull($this->samlResponses()->claim('handle-1'), 'Once.');
        self::assertNull($this->samlResponses()->claim('unknown'));
        self::assertNull($this->samlResponses()->claim(''));
    }

    #[Test]
    public function anAssertionIsAcceptedOncePerConnection(): void
    {
        $acme = ConnectionName::fromString('acme');

        self::assertTrue($this->samlAssertions()->claimAssertion($acme, '_a1', 300));
        self::assertFalse($this->samlAssertions()->claimAssertion($acme, '_a1', 300));
        self::assertTrue($this->samlAssertions()->claimAssertion($acme, '_a2', 300));
        self::assertTrue($this->samlAssertions()->claimAssertion(ConnectionName::fromString('other'), '_a1', 300));
    }
}
