<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);


namespace Clavia\Adapter\Secondary\Mail;

use Clavia\Application\Port\Mailer;
use Clavia\Application\Port\MailUnavailable;
use Clavia\Application\Port\OutgoingMail;
use Psr\Log\LoggerInterface;
use Symfony\Component\Mailer\Exception\TransportExceptionInterface;
use Symfony\Component\Mailer\Transport\Smtp\EsmtpTransport;
use Symfony\Component\Mailer\Transport\Smtp\Stream\SocketStream;
use Symfony\Component\Mailer\Transport\TransportInterface;
use Symfony\Component\Mime\Address;
use Symfony\Component\Mime\Email;
use Symfony\Component\Mime\Exception\RfcComplianceException;

/**
 * `CLAVIA_EMAIL_BACKEND=smtp`: delivery through the deployment's SMTP server, with
 * Symfony Mailer's ESMTP transport.
 *
 * Plain text only: a sign-in email carries a code or a link and nothing to render, and a
 * message without HTML has no remote images to track who opened it.
 */
final readonly class SmtpMailer implements Mailer
{
    /**
     * Seconds a silent mail server may hold up a sign-in. Someone is waiting on the page
     * for the answer; PHP's default socket timeout is a minute.
     */
    private const float TIMEOUT_SECONDS = 15.0;

    public function __construct(
        private TransportInterface $transport,
        private Address $from,
        private LoggerInterface $logger,
    ) {
    }

    /**
     * The transport for the settings: implicit TLS on port 465 (SMTPS); otherwise a
     * plaintext connection upgraded with STARTTLS — required, not merely attempted, unless
     * `CLAVIA_SMTP_STARTTLS=false`, so a man in the middle cannot strip the upgrade and
     * read the credentials and every code going out.
     *
     * @param non-empty-string $host
     * @param positive-int     $port
     */
    public static function transport(
        string $host,
        int $port,
        bool $startTls,
        ?string $username,
        #[\SensitiveParameter] ?string $password,
        LoggerInterface $logger,
    ): EsmtpTransport {
        $implicitTls = $port === 465;
        $transport = new EsmtpTransport($host, $port, $implicitTls, logger: $logger);
        $stream = $transport->getStream();
        if ($stream instanceof SocketStream) {
            $stream->setTimeout(self::TIMEOUT_SECONDS);
        }
        if (! $implicitTls) {
            $transport->setAutoTls($startTls);
            $transport->setRequireTls($startTls);
        }
        if ($username !== null && $username !== '') {
            $transport->setUsername($username);
            $transport->setPassword($password ?? '');
        }

        return $transport;
    }

    #[\Override]
    public function canSend(): bool
    {
        return true;
    }

    #[\Override]
    public function send(OutgoingMail $mail): void
    {
        try {
            $this->transport->send(
                new Email()
                    ->from($this->from)
                    ->to(new Address($mail->to))
                    ->subject($mail->subject)
                    ->text($mail->text),
            );
        } catch (TransportExceptionInterface | RfcComplianceException $failure) {
            // The recipient's domain is enough to diagnose a delivery problem; the
            // whole address is not the log's to keep.
            $at = strrpos($mail->to, '@');
            $this->logger->warning('Mail to a recipient at {domain} was not accepted: {reason}', [
                'domain' => $at === false ? '(no domain)' : substr($mail->to, $at + 1),
                'reason' => $failure->getMessage(),
            ]);

            throw new MailUnavailable('The message was not accepted for delivery.', 0, $failure);
        }
    }
}
