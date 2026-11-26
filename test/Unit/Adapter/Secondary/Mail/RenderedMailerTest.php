<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Adapter\Secondary\Mail;

use Clavia\Adapter\Secondary\Mail\MailTransport;
use Clavia\Adapter\Secondary\Mail\NoMailer;
use Clavia\Adapter\Secondary\Mail\RenderedMailer;
use Clavia\Application\Port\MailContent;
use Clavia\Application\Port\MailKind;
use Clavia\Application\Port\MailUnavailable;
use Clavia\Application\Port\OutgoingMail;
use Clavia\Application\Port\RenderedMail;
use Clavia\Domain\Shared\Language;
use Clavia\Domain\Shared\Languages;
use ClaviaTest\Support\Fake\InMemoryMessages;
use ClaviaTest\Support\Fake\RecordingMailTransport;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/** A mail worded in its language, then handed to the backend as it is sent. */
final class RenderedMailerTest extends TestCase
{
    private const array CATALOGUES = [
        'en' => [
            'mail.passwordless_link.subject' => 'Sign in to {site}',
            'mail.passwordless_link.text' => 'Open {link}; it expires in {expires}.',
            'mail.duration.minutes' => '{count, plural, one {# minute} other {# minutes}}',
            'mail.duration.hours' => '{count, plural, one {# hour} other {# hours}}',
        ],
        'fr' => [
            'mail.passwordless_link.subject' => 'Se connecter à {site}',
            'mail.passwordless_link.text' => 'Ouvrez {link} ; il expire dans {expires}.',
            'mail.duration.minutes' => '{count, plural, one {# minute} other {# minutes}}',
            'mail.duration.hours' => '{count, plural, one {# heure} other {# heures}}',
        ],
    ];

    public function testTheMailIsWordedInItsLanguageAndDelivered(): void
    {
        $transport = self::recording();

        self::mailer($transport)->send(self::link('fr', 900));

        self::assertEquals(
            [new RenderedMail(
                'ada@example.com',
                'Se connecter à acme.com',
                'Ouvrez https://x.test/l ; il expire dans 15 minutes.',
            )],
            $transport->delivered,
        );
    }

    /** Whole minutes rounded up under two hours, whole hours from there. */
    #[DataProvider('lifetimes')]
    public function testALifetimeIsWordedByTheLanguagesPluralRules(
        string $language,
        int $seconds,
        string $expires,
    ): void {
        $mail = self::mailer(self::recording())->render(self::link($language, $seconds));

        self::assertStringContainsString($expires, $mail->text);
    }

    /** @return iterable<string, array{string, positive-int, string}> */
    public static function lifetimes(): iterable
    {
        yield 'a minute' => ['en', 60, 'in 1 minute.'];
        yield 'ninety seconds is two minutes' => ['en', 90, 'in 2 minutes.'];
        yield 'just under two hours' => ['en', 7199, 'in 120 minutes.'];
        yield 'two hours' => ['en', 7200, 'in 2 hours.'];
        yield 'a day' => ['en', 86400, 'in 24 hours.'];
        yield 'French hours' => ['fr', 86400, 'dans 24 heures.'];
    }

    public function testWhatTheBackendRefusesIsRefused(): void
    {
        $this->expectException(MailUnavailable::class);

        self::mailer(new NoMailer())->send(self::link('en', 60));
    }

    public function testWhetherItCanSendIsTheBackends(): void
    {
        self::assertFalse(self::mailer(new NoMailer())->canSend());
        self::assertTrue(self::mailer(self::recording())->canSend());
    }

    /** @param positive-int $seconds */
    private static function link(string $language, int $seconds): OutgoingMail
    {
        return new OutgoingMail(
            'ada@example.com',
            new MailContent(MailKind::PasswordlessLink, ['site' => 'acme.com', 'link' => 'https://x.test/l'], $seconds),
            Language::fromString($language),
        );
    }

    private static function mailer(MailTransport $transport): RenderedMailer
    {
        $english = Language::fromString('en');
        $languages = Languages::of([$english, Language::fromString('fr')], $english);

        return new RenderedMailer($transport, new InMemoryMessages($languages, self::CATALOGUES));
    }

    private static function recording(): RecordingMailTransport
    {
        return new RecordingMailTransport();
    }
}
