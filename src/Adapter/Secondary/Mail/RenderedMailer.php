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
use Clavia\Application\Port\MailKind;
use Clavia\Application\Port\Messages;
use Clavia\Application\Port\OutgoingMail;
use Clavia\Application\Port\RenderedMail;
use Clavia\Domain\Shared\Language;

/**
 * The {@see Mailer}: words each mail from the catalogue in the mail's language, then hands it to the
 * backend (docs/design/translated-sign-in-pages.md §4, §5.3). The one place a mail's words come from.
 *
 * A lifetime is worded here too, by the catalogue's plural rules: whole minutes, rounded up, under two
 * hours ("expires in 2 minutes": a link good for 90 seconds does not expire "in 1 minute"), whole hours
 * beyond.
 */
final readonly class RenderedMailer implements Mailer
{
    public function __construct(
        public MailTransport $transport,
        private Messages $messages,
    ) {
    }

    #[\Override]
    public function canSend(): bool
    {
        return $this->transport->canSend();
    }

    #[\Override]
    public function send(OutgoingMail $mail): void
    {
        $this->transport->deliver($this->render($mail));
    }

    public function render(OutgoingMail $mail): RenderedMail
    {
        [$subject, $text] = self::keys($mail->content->kind);
        $values = $mail->content->values;
        if ($mail->content->lifetimeSeconds !== null) {
            $values['expires'] = $this->lifetime($mail->language, $mail->content->lifetimeSeconds);
        }

        return new RenderedMail(
            $mail->to,
            $this->messages->text($mail->language, $subject, $values),
            $this->messages->text($mail->language, $text, $values),
        );
    }

    /**
     * Each mail's subject and text in the catalogue, named in full so the catalogue's test finds them.
     *
     * @return array{non-empty-string, non-empty-string}
     */
    private static function keys(MailKind $kind): array
    {
        return match ($kind) {
            MailKind::Verification => ['mail.verification.subject', 'mail.verification.text'],
            MailKind::Reset => ['mail.reset.subject', 'mail.reset.text'],
            MailKind::Invitation => ['mail.invitation.subject', 'mail.invitation.text'],
            MailKind::AddressTaken => ['mail.address_taken.subject', 'mail.address_taken.text'],
            MailKind::SecondFactorEnrolled => [
                'mail.second_factor_enrolled.subject',
                'mail.second_factor_enrolled.text',
            ],
            MailKind::PasswordlessCode => ['mail.passwordless_code.subject', 'mail.passwordless_code.text'],
            MailKind::PasswordlessLink => ['mail.passwordless_link.subject', 'mail.passwordless_link.text'],
        };
    }

    /** @param positive-int $seconds */
    private function lifetime(Language $language, int $seconds): string
    {
        if ($seconds >= 7200) {
            return $this->messages->text($language, 'mail.duration.hours', ['count' => intdiv($seconds + 3599, 3600)]);
        }

        return $this->messages->text($language, 'mail.duration.minutes', ['count' => intdiv($seconds + 59, 60)]);
    }
}
