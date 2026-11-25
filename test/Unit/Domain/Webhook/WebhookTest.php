<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Domain\Webhook;

use Clavia\Domain\Audit\AuditEventType;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\Url;
use Clavia\Domain\Webhook\EventFilter;
use Clavia\Domain\Webhook\WebhookDisabledReason;
use Clavia\Domain\Webhook\WebhookEndpoint;
use Clavia\Domain\Webhook\WebhookEndpointId;
use Clavia\Domain\Webhook\WebhookSecret;
use ClaviaTest\Support\Fake\SeededRandomSource;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** An endpoint, its secret and its filter (docs/design/webhooks.md §2, §4). */
final class WebhookTest extends TestCase
{
    public function testASecretIsWhsecAndThirtyTwoRandomBytes(): void
    {
        $secret = WebhookSecret::generate(new SeededRandomSource(1));

        self::assertMatchesRegularExpression('/^whsec_[A-Za-z0-9+\/]{43}=$/D', $secret->reveal());
        self::assertSame(32, strlen($secret->key()));
        self::assertNotSame($secret->reveal(), WebhookSecret::generate(new SeededRandomSource(2))->reveal());
    }

    public function testASecretIsNeverPrinted(): void
    {
        $secret = WebhookSecret::generate(new SeededRandomSource(1));

        self::assertStringNotContainsString($secret->reveal(), print_r($secret, true));
        self::assertSame(['value' => '(hidden)'], $secret->__debugInfo(), 'What var_dump() shows.');
        self::assertSame('{}', json_encode($secret));
    }

    public function testAFilterIsAllOrTheTypesNamed(): void
    {
        self::assertSame(['*'], EventFilter::fromStrings(['*'])->toStrings());
        self::assertTrue(EventFilter::all()->matches(AuditEventType::TokenIssued));

        $users = EventFilter::fromStrings(['user.deleted', 'user.created']);
        self::assertSame(['user.created', 'user.deleted'], $users->toStrings(), 'Sorted.');
        self::assertTrue($users->matches(AuditEventType::UserCreated));
        self::assertFalse($users->matches(AuditEventType::TokenIssued));
    }

    /** @return iterable<string, array{list<string>}> */
    public static function badFilters(): iterable
    {
        yield 'nothing' => [[]];
        yield 'an unknown type' => [['user.exploded']];
        yield '* with a type' => [['*', 'user.created']];
        yield 'a type twice' => [['user.created', 'user.created']];
    }

    /** @param list<string> $names */
    #[DataProvider('badFilters')]
    public function testAFilterNamesKnownTypesOnce(array $names): void
    {
        $this->expectException(InvalidValue::class);

        EventFilter::fromStrings($names);
    }

    /** @return iterable<string, array{string}> */
    public static function badUrls(): iterable
    {
        yield 'http' => ['http://hooks.example/audit'];
        yield 'a fragment' => ['https://hooks.example/audit#here'];
    }

    #[DataProvider('badUrls')]
    public function testAnEndpointIsAnHttpsUrlWithoutAFragment(string $url): void
    {
        $this->expectException(InvalidValue::class);

        self::endpoint($url);
    }

    public function testADescriptionIsOneShortLine(): void
    {
        self::assertSame(
            str_repeat('é', 120),
            self::endpoint()->described(str_repeat('é', 120), new DateTimeImmutable())->description,
        );

        $this->expectException(InvalidValue::class);
        self::endpoint()->described("two\nlines", new DateTimeImmutable());
    }

    public function testThePreviousSecretSignsForADayAfterARotation(): void
    {
        $at = new DateTimeImmutable('2026-01-15T10:00:00Z');
        $rotated = self::endpoint()->rotatedTo('sealed-2', $at);

        self::assertSame('sealed-2', $rotated->sealedSecret);
        self::assertSame('sealed-1', $rotated->previousSecretAt($at->modify('+23 hours')));
        self::assertNull($rotated->previousSecretAt($at->modify('+24 hours')));
        self::assertNull(self::endpoint()->previousSecretAt($at), 'None before any rotation.');
    }

    public function testATestEventIsNeverSubscribedToNotEvenPastTheWildcard(): void
    {
        self::assertFalse(EventFilter::all()->matches(AuditEventType::WebhookTested));
        self::assertTrue(EventFilter::all()->matches(AuditEventType::WebhookDisabled));

        $this->expectException(InvalidValue::class);
        EventFilter::fromStrings(['webhook.tested']);
    }

    public function testSwitchingAnEndpointOnOrOffStartsTheFailureClockOver(): void
    {
        $now = new DateTimeImmutable('2026-03-04T09:00:00Z');
        $failing = WebhookEndpoint::reconstitute(
            WebhookEndpointId::generate(new SeededRandomSource(1)),
            Url::fromString('https://hooks.example/'),
            '',
            EventFilter::all(),
            false,
            'sealed',
            null,
            null,
            $now,
            $now,
            $now->modify('-6 days'),
            WebhookDisabledReason::Failing,
        );

        $on = $failing->enabled(true, $now);
        self::assertTrue($on->isEnabled);
        self::assertNull($on->failingSince);
        self::assertNull($on->disabledReason);
        self::assertSame(WebhookDisabledReason::Operator, $on->enabled(false, $now)->disabledReason);
        self::assertEquals($now->modify('-5 days'), WebhookEndpoint::deadIfFailingBefore($now));
    }

    private static function endpoint(string $url = 'https://hooks.example/audit'): WebhookEndpoint
    {
        return WebhookEndpoint::register(
            WebhookEndpointId::generate(new SeededRandomSource(1)),
            Url::fromString($url),
            'SIEM',
            EventFilter::all(),
            'sealed-1',
            new DateTimeImmutable('2026-01-15T09:00:00Z'),
        );
    }
}
