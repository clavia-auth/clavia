<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Contract;

use Clavia\Application\Port\PasswordlessChallengeStore;
use Clavia\Domain\Authentication\OneTimeCode;
use Clavia\Domain\Authentication\PasswordlessChallenge;
use Clavia\Domain\Authentication\PasswordlessMode;
use Clavia\Domain\Client\ClientId;
use PHPUnit\Framework\Attributes\Test;

/**
 * What every {@see PasswordlessChallengeStore} must do. Expiry is asserted by each
 * implementation's own test.
 */
trait PasswordlessChallengeStoreContract
{
    abstract protected function challenges(): PasswordlessChallengeStore;

    #[Test]
    public function aCodeChallengeIsReadBackWhole(): void
    {
        $code = OneTimeCode::fromTyped('042042');
        $this->challenges()->open('handle-1', PasswordlessChallenge::forCode(
            'jane@example.com',
            'handle-1',
            $code,
            '/oauth2/authorize?client_id=spa&state=é%20x',
            ClientId::fromString('spa'),
            'login-state',
        ), 300);

        $challenge = $this->challenges()->find('handle-1');

        self::assertNotNull($challenge);
        self::assertSame('jane@example.com', $challenge->email);
        self::assertSame(PasswordlessMode::Code, $challenge->mode);
        self::assertTrue($challenge->acceptsCode('handle-1', $code));
        self::assertSame('/oauth2/authorize?client_id=spa&state=é%20x', $challenge->nextUrl);
        self::assertSame('spa', $challenge->clientId?->value);
        self::assertSame('login-state', $challenge->loginState);
        self::assertSame(0, $challenge->attempts);
    }

    #[Test]
    public function aLinkChallengeKeepsNoCodeAndMayHaveNoClientOrLoginState(): void
    {
        $this->challenges()->open('link-1', PasswordlessChallenge::forLink('jane@example.com', '/', null, null), 300);

        $challenge = $this->challenges()->find('link-1');

        self::assertNotNull($challenge);
        self::assertTrue($challenge->isLink());
        self::assertNull($challenge->codeDigest);
        self::assertNull($challenge->clientId);
        self::assertNull($challenge->loginState);
    }

    #[Test]
    public function anUnknownOrEmptyHandleIsNull(): void
    {
        $this->challenges()->open('link-1', PasswordlessChallenge::forLink('jane@example.com', '/', null, null), 300);

        self::assertNull($this->challenges()->find('link-2'));
        self::assertNull($this->challenges()->find(''));
        self::assertNull($this->challenges()->claim(''));
        self::assertFalse($this->challenges()->recordFailure('', 5));
    }

    #[Test]
    public function failuresAreCountedAndTheLastOneDestroysTheChallenge(): void
    {
        $this->challenges()->open('link-1', PasswordlessChallenge::forLink('jane@example.com', '/', null, null), 300);

        self::assertTrue($this->challenges()->recordFailure('link-1', 3));
        self::assertTrue($this->challenges()->recordFailure('link-1', 3));
        self::assertSame(2, $this->challenges()->find('link-1')?->attempts);
        self::assertFalse($this->challenges()->recordFailure('link-1', 3));
        self::assertNull($this->challenges()->find('link-1'));
        self::assertFalse($this->challenges()->recordFailure('link-1', 3), 'Nothing left to count against.');
    }

    #[Test]
    public function aChallengeIsClaimedOnce(): void
    {
        $this->challenges()->open('link-1', PasswordlessChallenge::forLink('jane@example.com', '/', null, null), 300);

        self::assertSame('jane@example.com', $this->challenges()->claim('link-1')?->email);
        self::assertNull($this->challenges()->claim('link-1'));
        self::assertNull($this->challenges()->find('link-1'));
    }
}
