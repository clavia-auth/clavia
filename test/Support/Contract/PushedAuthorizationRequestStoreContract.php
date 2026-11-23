<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Contract;

use Clavia\Application\Port\PushedAuthorizationRequestStore;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\OAuth2\PushedAuthorizationRequest;
use PHPUnit\Framework\Attributes\Test;

/**
 * What every {@see PushedAuthorizationRequestStore} must do — the Redis adapter and the double.
 */
trait PushedAuthorizationRequestStoreContract
{
    abstract protected function pushedRequests(): PushedAuthorizationRequestStore;

    #[Test]
    public function aPushedRequestIsReadBackWholeAsOftenAsAsked(): void
    {
        $this->pushedRequests()->push('handle-1', $this->aRequest(), 60);

        $first = $this->pushedRequests()->find('handle-1');
        $again = $this->pushedRequests()->find('handle-1');

        self::assertNotNull($first);
        self::assertSame('spa', $first->clientId->value);
        self::assertSame([['response_type', 'code'], ['scope', 'openid é'], ['scope', 'twice']], $first->parameters);
        self::assertEquals($first, $again);
    }

    #[Test]
    public function aRequestIsSpentOnceAndThenGone(): void
    {
        $this->pushedRequests()->push('handle-1', $this->aRequest(), 60);

        self::assertTrue($this->pushedRequests()->spend('handle-1'));
        self::assertFalse($this->pushedRequests()->spend('handle-1'));
        self::assertNull($this->pushedRequests()->find('handle-1'));
    }

    #[Test]
    public function anUnknownOrEmptyHandleIsNothing(): void
    {
        $this->pushedRequests()->push('handle-1', $this->aRequest(), 60);

        self::assertNull($this->pushedRequests()->find('handle-2'));
        self::assertNull($this->pushedRequests()->find(''));
        self::assertFalse($this->pushedRequests()->spend(''));
    }

    private function aRequest(): PushedAuthorizationRequest
    {
        return new PushedAuthorizationRequest(
            ClientId::fromString('spa'),
            [['response_type', 'code'], ['scope', 'openid é'], ['scope', 'twice']],
        );
    }
}
