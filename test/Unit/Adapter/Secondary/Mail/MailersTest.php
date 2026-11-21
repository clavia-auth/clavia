<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);


namespace ClaviaTest\Unit\Adapter\Secondary\Mail;

use Clavia\Adapter\Secondary\Mail\NoMailer;
use Clavia\Adapter\Secondary\Mail\OutboxMailer;
use Clavia\Adapter\Secondary\Mail\SmtpMailer;
use Clavia\Application\Port\MailUnavailable;
use Clavia\Application\Port\OutgoingMail;
use ClaviaTest\Support\Fake\InMemoryMailOutbox;
use ClaviaTest\Support\Fake\RecordingTransport;
use ClaviaTest\Support\RecordingLogger;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Component\Mailer\Exception\TransportException;
use Symfony\Component\Mailer\Transport\Smtp\Stream\SocketStream;
use Symfony\Component\Mime\Address;
use Symfony\Component\Mime\Email;

final class MailersTest extends TestCase
{
    public function testTheNoneBackendSendsNothingAndSaysSo(): void
    {
        $mailer = new NoMailer();

        self::assertFalse($mailer->canSend());
        $this->expectException(MailUnavailable::class);
        $mailer->send(self::mail());
    }

    public function testTheConsoleBackendKeepsAndLogsEachMessage(): void
    {
        $outbox = new InMemoryMailOutbox();
        $logger = new RecordingLogger();
        $mailer = new OutboxMailer($outbox, $logger);

        $mailer->send(self::mail());

        self::assertTrue($mailer->canSend());
        self::assertSame('Your sign-in code is 123456', $outbox->recent(1)[0]->text ?? null);
        self::assertTrue($logger->hasRecordContaining('Mail (console backend)'));
    }

    public function testSmtpSendsAPlainTextMessageFromTheDeployment(): void
    {
        $transport = new RecordingTransport();
        $mailer = new SmtpMailer($transport, new Address('no-reply@acme.com'), new NullLogger());

        $mailer->send(self::mail());

        $sent = $transport->sent[0] ?? null;
        self::assertInstanceOf(Email::class, $sent);
        self::assertSame('no-reply@acme.com', $sent->getFrom()[0]->getAddress());
        self::assertSame('jane@example.com', $sent->getTo()[0]->getAddress());
        self::assertSame('Your sign-in code for acme.com', $sent->getSubject());
        self::assertSame('Your sign-in code is 123456', $sent->getTextBody());
        self::assertNull($sent->getHtmlBody(), 'Nothing to render, nothing to track.');
    }

    public function testAMessageTheServerRefusesIsMailUnavailableAndLogsOnlyTheDomain(): void
    {
        $transport = new RecordingTransport(failing: true);
        $logger = new RecordingLogger();
        $mailer = new SmtpMailer($transport, new Address('no-reply@acme.com'), $logger);

        try {
            $mailer->send(self::mail());
            self::fail('A refused message was reported as sent.');
        } catch (MailUnavailable $unavailable) {
            self::assertInstanceOf(TransportException::class, $unavailable->getPrevious());
        }
        self::assertTrue($logger->hasRecordContaining('example.com'));
        self::assertFalse($logger->hasRecordContaining('jane@'), 'The address is not the log\'s to keep.');
    }

    public function testStartTlsIsRequiredUnlessSwitchedOffAndPort465IsImplicitTls(): void
    {
        $required = SmtpMailer::transport('smtp.acme.com', 587, true, 'user', 'secret', new NullLogger());
        $optional = SmtpMailer::transport('smtp.acme.com', 25, false, null, null, new NullLogger());
        $implicit = SmtpMailer::transport('smtp.acme.com', 465, true, null, null, new NullLogger());

        self::assertTrue($required->isTlsRequired());
        self::assertTrue($required->isAutoTls());
        self::assertSame('user', $required->getUsername());
        self::assertSame('secret', $required->getPassword());
        self::assertFalse($optional->isTlsRequired());
        self::assertFalse($optional->isAutoTls());
        self::assertSame('', $optional->getUsername());
        self::assertStringStartsWith('smtps://', (string) $implicit);
        $stream = $required->getStream();
        self::assertInstanceOf(SocketStream::class, $stream);
        self::assertSame(15.0, $stream->getTimeout(), 'Someone is waiting on the page.');
    }

    private static function mail(): OutgoingMail
    {
        return new OutgoingMail('jane@example.com', 'Your sign-in code for acme.com', 'Your sign-in code is 123456');
    }
}
