<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Domain\OAuth2;

use Clavia\Domain\Authentication\AuthenticationContext;
use Clavia\Domain\Authentication\AuthenticationMethod;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Identity\UserId;
use Clavia\Domain\OAuth2\DeviceAuthorization;
use Clavia\Domain\OAuth2\DeviceDecision;
use Clavia\Domain\OAuth2\DevicePoll;
use Clavia\Domain\OAuth2\UserCode;
use Clavia\Domain\Shared\Digest;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\ScopeSet;
use ClaviaTest\Support\Fake\SeededRandomSource;
use DateTimeImmutable;
use LogicException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * A device's request for access: the user code a person types, and the polling rules of
 * RFC 8628 §3.5.
 */
final class DeviceAuthorizationRulesTest extends TestCase
{
    private const string START = '2026-01-15T10:00:00Z';

    // ── The user code ───────────────────────────────────────────────────────────

    public function testAUserCodeIsEightConsonantsInTwoGroups(): void
    {
        $random = new SeededRandomSource(7);
        for ($i = 0; $i < 50; ++$i) {
            $code = UserCode::generate($random)->value;

            self::assertMatchesRegularExpression('/^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$/D', $code);
        }
    }

    public function testWhatAPersonTypesIsForgiven(): void
    {
        foreach (['BCDF-GHJK', 'bcdf-ghjk', 'bcdfghjk', ' bcdf ghjk ', 'BcDf--GhJk'] as $typed) {
            self::assertSame('BCDF-GHJK', UserCode::fromTyped($typed)->value, $typed);
        }
    }

    #[DataProvider('notUserCodes')]
    public function testWhatCannotBeAUserCodeIsRefused(string $typed): void
    {
        $this->expectException(InvalidValue::class);

        UserCode::fromTyped($typed);
    }

    /** @return iterable<string, array{string}> */
    public static function notUserCodes(): iterable
    {
        yield 'empty' => [''];
        yield 'too short' => ['BCDF-GHJ'];
        yield 'too long' => ['BCDF-GHJKL'];
        yield 'a vowel' => ['BCDF-GHJA'];
        yield 'a digit' => ['BCDF-GHJ1'];
        yield 'punctuation' => ['BCDF.GHJK'];
    }

    // ── Polling ─────────────────────────────────────────────────────────────────

    public function testUntilSomebodyDecidesTheDeviceIsToldToWait(): void
    {
        $request = $this->aRequest();

        self::assertSame(DevicePoll::Pending, $request->poll($this->at(0)));
        self::assertSame(DevicePoll::Pending, $request->poll($this->at(5)));
        self::assertEquals($this->at(5), $request->lastPolledAt());
    }

    public function testPollingSoonerThanTheIntervalSlowsTheDeviceDownForGood(): void
    {
        $request = $this->aRequest();
        $request->poll($this->at(0));

        self::assertSame(DevicePoll::SlowDown, $request->poll($this->at(4)));
        self::assertSame(10, $request->interval());
        // The interval it now has to keep is the longer one.
        self::assertSame(DevicePoll::SlowDown, $request->poll($this->at(13)));
        self::assertSame(15, $request->interval());
        self::assertSame(DevicePoll::Pending, $request->poll($this->at(28)));
    }

    public function testADecisionIsHeardWheneverTheDeviceAsks(): void
    {
        $approved = $this->aRequest();
        $approved->poll($this->at(0));
        $approved->approve($this->aUser(), $this->signedIn(), $this->at(1));

        $denied = $this->aRequest();
        $denied->deny($this->aUser(), $this->at(1));

        self::assertSame(DevicePoll::Approved, $approved->poll($this->at(2)));
        self::assertSame(DevicePoll::Denied, $denied->poll($this->at(2)));
        self::assertSame(['pwd'], $approved->authentication()?->methodValues());
        self::assertNull($denied->authentication());
    }

    public function testAnExpiredRequestSaysSoWhateverItsState(): void
    {
        $pending = $this->aRequest();
        $approved = $this->aRequest();
        $approved->approve($this->aUser(), $this->signedIn(), $this->at(1));

        self::assertSame(DevicePoll::Expired, $pending->poll($this->at(600)));
        self::assertSame(DevicePoll::Expired, $approved->poll($this->at(601)));
    }

    // ── Deciding ────────────────────────────────────────────────────────────────

    public function testARequestIsDecidedOnceAndNotAfterItExpires(): void
    {
        $request = $this->aRequest();
        self::assertTrue($request->awaitsDecisionAt($this->at(1)));
        $request->deny($this->aUser(), $this->at(1));

        self::assertSame(DeviceDecision::Denied, $request->decision());
        self::assertFalse($request->awaitsDecisionAt($this->at(2)));
        self::assertFalse($this->aRequest()->awaitsDecisionAt($this->at(600)));

        $this->expectException(LogicException::class);

        $request->approve($this->aUser(), $this->signedIn(), $this->at(2));
    }

    public function testItIsKeptAMinuteBeyondItsLife(): void
    {
        self::assertSame(660, $this->aRequest()->retentionFrom($this->at(0)));
        self::assertSame(1, $this->aRequest()->retentionFrom($this->at(10_000)));
    }

    public function testAStoredRequestIsCoherent(): void
    {
        $this->expectException(LogicException::class);

        DeviceAuthorization::reconstitute(
            Digest::of('device-code'),
            UserCode::fromTyped('BCDF-GHJK'),
            ClientId::fromString('tv'),
            ScopeSet::fromString('openid'),
            null,
            $this->at(600),
            5,
            DeviceDecision::Approved,
            null,
            null,
            null,
        );
    }

    private function aRequest(): DeviceAuthorization
    {
        return DeviceAuthorization::request(
            Digest::of('device-code'),
            UserCode::fromTyped('BCDF-GHJK'),
            ClientId::fromString('tv'),
            ScopeSet::fromString('openid profile'),
            null,
            $this->at(0),
            600,
            5,
        );
    }

    private function aUser(): UserId
    {
        return UserId::generate(new SeededRandomSource(3));
    }

    private function signedIn(): AuthenticationContext
    {
        return AuthenticationContext::reconstitute($this->at(-60), [AuthenticationMethod::Password]);
    }

    private function at(int $seconds): DateTimeImmutable
    {
        return new DateTimeImmutable(self::START)->modify(sprintf('%+d seconds', $seconds));
    }
}
