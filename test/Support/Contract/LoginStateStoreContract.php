<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Contract;

use Clavia\Application\Port\LoginStateStore;
use Clavia\Domain\Authentication\LoginState;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\OAuth2\UiLocales;
use PHPUnit\Framework\Attributes\Test;

/**
 * What every {@see LoginStateStore} must do. Expiry is asserted by each implementation's
 * own test: how time passes is not the same for an array and for Redis.
 */
trait LoginStateStoreContract
{
    abstract protected function loginStates(): LoginStateStore;

    #[Test]
    public function whatWasPutIsReadBack(): void
    {
        $this->loginStates()->put('handle-1', new LoginState(
            '/oauth2/authorize?client_id=spa&state=é%20x',
            ClientId::fromString('spa'),
        ));

        $state = $this->loginStates()->get('handle-1');

        self::assertNotNull($state);
        self::assertSame('/oauth2/authorize?client_id=spa&state=é%20x', $state->nextUrl);
        self::assertSame('spa', $state->clientId?->value);
    }

    #[Test]
    public function aStateWithoutAClientKeepsNone(): void
    {
        $this->loginStates()->put('handle-1', new LoginState('/'));

        self::assertNull($this->loginStates()->get('handle-1')?->clientId);
        self::assertSame('/', $this->loginStates()->get('handle-1')?->nextUrl);
    }

    #[Test]
    public function readingDoesNotConsume(): void
    {
        $this->loginStates()->put('handle-1', new LoginState('/a'));

        $this->loginStates()->get('handle-1');

        self::assertNotNull($this->loginStates()->get('handle-1'));
    }

    #[Test]
    public function anUnknownOrEmptyHandleIsNull(): void
    {
        $this->loginStates()->put('handle-1', new LoginState('/a'));

        self::assertNull($this->loginStates()->get('handle-2'));
        self::assertNull($this->loginStates()->get(''));
        self::assertNull($this->loginStates()->get('*'));
    }

    #[Test]
    public function aForgottenHandleIsGoneAndOnlyThatOne(): void
    {
        $this->loginStates()->put('handle-1', new LoginState('/a'));
        $this->loginStates()->put('handle-2', new LoginState('/b'));

        $this->loginStates()->forget('handle-1');
        $this->loginStates()->forget('never-there');
        $this->loginStates()->forget('');

        self::assertNull($this->loginStates()->get('handle-1'));
        self::assertSame('/b', $this->loginStates()->get('handle-2')?->nextUrl);
    }

    /** docs/design/translated-sign-in-pages.md §5.2: the pages a held request goes through read them here. */
    #[Test]
    public function theLanguagesTheRequestAskedForAreKept(): void
    {
        $this->loginStates()->put('handle-1', new LoginState('/a', null, UiLocales::fromString('fr-CA fr')));
        $this->loginStates()->put('handle-2', new LoginState('/b'));

        self::assertSame(['fr-CA', 'fr'], $this->loginStates()->get('handle-1')?->uiLocales->tags);
        self::assertSame([], $this->loginStates()->get('handle-2')?->uiLocales->tags);
    }
}
