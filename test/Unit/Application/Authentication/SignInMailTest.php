<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Application\Authentication;

use Clavia\Application\Authentication\Passwordless\SignInMail;
use Clavia\Application\Port\MailKind;
use Clavia\Domain\Authentication\OneTimeCode;
use Clavia\Domain\Shared\Language;
use ClaviaTest\Support\TestMail;
use PHPUnit\Framework\TestCase;

/** The passwordless mails: what each carries, worded by the shipped catalogue. */
final class SignInMailTest extends TestCase
{
    public function testTheCodeMessageSaysWhatTheCodeIsGoodForAndForHowLong(): void
    {
        $outgoing = new SignInMail('acme.com', 'https://auth.acme.com', 600, 90)
            ->code('jane@example.com', OneTimeCode::fromTyped('012345'), Language::fromString('en'));
        $mail = TestMail::render($outgoing);

        self::assertSame(MailKind::PasswordlessCode, $outgoing->content->kind);
        self::assertSame('jane@example.com', $mail->to);
        self::assertSame('Your sign-in code for acme.com', $mail->subject);
        self::assertStringContainsString('Your sign-in code is 012345', $mail->text);
        self::assertStringContainsString('expires in 10 minutes', $mail->text);
        self::assertStringContainsString('ignore this email', $mail->text);
    }

    public function testTheLinkMessageLeadsToTheConfirmationPageAndRoundsUp(): void
    {
        $english = Language::fromString('en');
        $mail = TestMail::render(
            new SignInMail('acme.com', 'https://auth.acme.com/', 600, 90)->link('jane@example.com', 'a-b_c', $english),
        );

        self::assertSame('Sign in to acme.com', $mail->subject);
        self::assertStringContainsString("https://auth.acme.com/auth/passwordless/verify?token=a-b_c\n", $mail->text);
        self::assertStringContainsString('expires in 2 minutes', $mail->text);
        $oneMinute = new SignInMail('acme.com', 'https://auth.acme.com', 600, 60)
            ->link('jane@example.com', 't', $english);
        self::assertStringContainsString('expires in 1 minute.', TestMail::render($oneMinute)->text);
    }

    public function testTheMailIsInTheLanguageItWasComposedFor(): void
    {
        $mail = TestMail::render(
            new SignInMail('acme.com', 'https://auth.acme.com', 600, 90)
                ->code('jane@example.com', OneTimeCode::fromTyped('012345'), Language::fromString('fr')),
        );

        self::assertSame('Votre code de connexion pour acme.com', $mail->subject);
        self::assertStringContainsString('Votre code de connexion est 012345', $mail->text);
        self::assertStringContainsString('expire dans 10 minutes', $mail->text);
    }
}
