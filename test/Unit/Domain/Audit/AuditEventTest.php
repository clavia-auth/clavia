<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Domain\Audit;

use Clavia\Domain\Audit\Actor;
use Clavia\Domain\Audit\AuditEvent;
use Clavia\Domain\Audit\AuditEventId;
use Clavia\Domain\Audit\AuditEventType;
use Clavia\Domain\Audit\Outcome;
use Clavia\Domain\Shared\InvalidValue;
use ClaviaTest\Support\Fake\SeededRandomSource;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * What an audit event agrees to hold: short, named facts — never a credential.
 */
final class AuditEventTest extends TestCase
{
    /** @return iterable<string, array{string}> */
    public static function credentialNames(): iterable
    {
        $names = [
            'client_secret',
            'password',
            'new_passwd',
            'refresh_token',
            'credential_id',
            'client_assertion',
            'code_verifier',
            'private_key',
            'session_cookie',
        ];
        foreach ($names as $name) {
            yield $name => [$name];
        }
    }

    #[DataProvider('credentialNames')]
    public function testADetailNamingACredentialIsRefused(string $name): void
    {
        $this->expectException(InvalidValue::class);
        $this->expectExceptionMessage('never holds a credential');

        self::event([$name => 'x']);
    }

    /** @return iterable<string, array{string}> */
    public static function malformedNames(): iterable
    {
        yield 'camel case' => ['grantType'];
        yield 'a dash' => ['grant-type'];
        yield 'a leading digit' => ['2fa'];
        yield 'empty' => [''];
        yield 'too long' => [str_repeat('a', 65)];
    }

    #[DataProvider('malformedNames')]
    public function testADetailNameIsSnakeCase(string $name): void
    {
        $this->expectException(InvalidValue::class);

        self::event([$name => 'x']);
    }

    public function testThereAreAtMostSixteenDetails(): void
    {
        $details = [];
        for ($i = 0; $i <= AuditEvent::MAX_DETAILS; $i++) {
            $details['detail_' . $i] = $i;
        }

        $this->expectException(InvalidValue::class);

        self::event($details);
    }

    public function testNullDetailsAreLeftOutAndCountForNothing(): void
    {
        $details = ['audience' => null];
        for ($i = 0; $i < AuditEvent::MAX_DETAILS; $i++) {
            $details['detail_' . $i] = true;
        }

        $event = self::event($details);

        self::assertArrayNotHasKey('audience', $event->details);
        self::assertCount(AuditEvent::MAX_DETAILS, $event->details);
    }

    public function testLongValuesAreCutNotRefused(): void
    {
        // An address typed at the login page reaches the trail as it came: a failed
        // sign-in is recorded, whatever was typed.
        $typed = str_repeat('é', 400);

        $event = self::event(['email' => $typed, 'fields' => array_fill(0, 20, $typed)], userAgent: $typed);

        self::assertIsString($event->details['email']);
        self::assertSame(AuditEvent::MAX_VALUE_LENGTH, strlen($event->details['email']));
        self::assertTrue(mb_check_encoding($event->details['email'], 'UTF-8'), 'cut on a character boundary');
        self::assertIsArray($event->details['fields']);
        self::assertCount(AuditEvent::MAX_DETAILS, $event->details['fields']);
        self::assertSame(AuditEvent::MAX_VALUE_LENGTH, strlen((string) $event->userAgent));
    }

    public function testValuesKeepTheirTypes(): void
    {
        $event = self::event(['refreshable' => false, 'count' => 3, 'amr' => ['pwd', 'otp']]);

        self::assertSame(['refreshable' => false, 'count' => 3, 'amr' => ['pwd', 'otp']], $event->details);
    }

    /**
     * @param array<string, string|int|bool|list<string>|null> $details
     */
    private static function event(array $details, ?string $userAgent = null): AuditEvent
    {
        return AuditEvent::record(
            AuditEventId::generate(new SeededRandomSource()),
            AuditEventType::ClientUpdated,
            new DateTimeImmutable('2026-01-15T10:00:00Z'),
            Actor::system(),
            null,
            Outcome::Success,
            $details,
            userAgent: $userAgent,
        );
    }
}
