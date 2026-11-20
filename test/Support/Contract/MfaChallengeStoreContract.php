<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Contract;

use Clavia\Application\Port\MfaChallengeStore;
use Clavia\Domain\Authentication\AuthenticationMethod;
use Clavia\Domain\Authentication\MfaChallenge;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Identity\UserId;
use PHPUnit\Framework\Attributes\Test;

/**
 * What every {@see MfaChallengeStore} must do. Expiry is asserted by each
 * implementation's own test.
 */
trait MfaChallengeStoreContract
{
    abstract protected function challenges(): MfaChallengeStore;

    #[Test]
    public function anOpenedChallengeIsReadBackWhole(): void
    {
        $this->challenges()->open('handle-1', $this->aChallenge(ClientId::fromString('spa')), 300);

        $challenge = $this->challenges()->find('handle-1');

        self::assertNotNull($challenge);
        self::assertSame('0190a4f2-7c1e-7b3a-9c2d-5e6f7a8b9c0d', $challenge->userId->value);
        self::assertSame('/oauth2/authorize?client_id=spa&state=é%20x', $challenge->nextUrl);
        self::assertSame('spa', $challenge->clientId?->value);
        self::assertSame([AuthenticationMethod::Password], $challenge->firstFactor);
        self::assertSame(0, $challenge->attempts);
    }

    #[Test]
    public function aChallengeWithoutAClientKeepsNone(): void
    {
        $this->challenges()->open('handle-1', $this->aChallenge(null), 300);

        self::assertNull($this->challenges()->find('handle-1')?->clientId);
    }

    #[Test]
    public function anUnknownOrEmptyHandleIsNull(): void
    {
        $this->challenges()->open('handle-1', $this->aChallenge(null), 300);

        self::assertNull($this->challenges()->find('handle-2'));
        self::assertNull($this->challenges()->find(''));
    }

    #[Test]
    public function failuresAreCountedAndTheLimitDestroysTheChallenge(): void
    {
        $this->challenges()->open('handle-1', $this->aChallenge(null), 300);

        self::assertTrue($this->challenges()->recordFailure('handle-1', 3));
        self::assertTrue($this->challenges()->recordFailure('handle-1', 3));
        self::assertSame(2, $this->challenges()->find('handle-1')?->attempts);

        self::assertFalse($this->challenges()->recordFailure('handle-1', 3));
        self::assertNull($this->challenges()->find('handle-1'));
    }

    #[Test]
    public function aFailureOnAChallengeThatIsNotThereBringsNothingBack(): void
    {
        self::assertFalse($this->challenges()->recordFailure('never-there', 5));
        self::assertFalse($this->challenges()->recordFailure('', 5));

        self::assertNull($this->challenges()->find('never-there'));
    }

    #[Test]
    public function aClosedChallengeIsGoneAndOnlyThatOne(): void
    {
        $this->challenges()->open('handle-1', $this->aChallenge(null), 300);
        $this->challenges()->open('handle-2', $this->aChallenge(null), 300);

        $this->challenges()->close('handle-1');
        $this->challenges()->close('never-there');
        $this->challenges()->close('');

        self::assertNull($this->challenges()->find('handle-1'));
        self::assertNotNull($this->challenges()->find('handle-2'));
    }

    private function aChallenge(?ClientId $clientId): MfaChallenge
    {
        return new MfaChallenge(
            UserId::fromString('0190a4f2-7c1e-7b3a-9c2d-5e6f7a8b9c0d'),
            '/oauth2/authorize?client_id=spa&state=é%20x',
            $clientId,
            [AuthenticationMethod::Password],
        );
    }
}
