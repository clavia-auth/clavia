<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Adapter\Secondary\Redis;

use Clavia\Application\Port\MailOutbox;
use Clavia\Application\Port\RenderedMail;
use JsonException;

/**
 * The development outbox in Redis: a list under `mail-outbox`, newest first, cut to the
 * last fifty messages so it never grows.
 */
final readonly class RedisMailOutbox implements MailOutbox
{
    private const string KEY = 'mail-outbox';

    private const int SIZE = 50;

    public function __construct(private RedisConnection $redis)
    {
    }

    #[\Override]
    public function record(RenderedMail $mail): void
    {
        $client = $this->redis->client();
        $client->multi();
        $client->lPush(self::KEY, json_encode(
            ['to' => $mail->to, 'subject' => $mail->subject, 'text' => $mail->text],
            JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE,
        ));
        $client->lTrim(self::KEY, 0, self::SIZE - 1);
        $client->exec();
    }

    #[\Override]
    public function recent(int $limit): array
    {
        /** @var mixed $entries */
        $entries = $this->redis->client()->lRange(self::KEY, 0, min($limit, self::SIZE) - 1);
        if (! is_array($entries)) {
            return [];
        }

        $mails = [];
        foreach (array_filter($entries, is_string(...)) as $entry) {
            $mail = self::decode($entry);
            if ($mail !== null) {
                $mails[] = $mail;
            }
        }

        return $mails;
    }

    /** An entry this code cannot read is an entry that is not there. */
    private static function decode(string $entry): ?RenderedMail
    {
        try {
            /** @var mixed $fields */
            $fields = json_decode($entry, true, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return null;
        }
        if (! is_array($fields)) {
            return null;
        }
        /** @var mixed $to */
        $to = $fields['to'] ?? null;
        /** @var mixed $subject */
        $subject = $fields['subject'] ?? null;
        /** @var mixed $text */
        $text = $fields['text'] ?? null;
        if (! is_string($to) || $to === '' || ! is_string($subject) || $subject === '' || ! is_string($text)) {
            return null;
        }

        return new RenderedMail($to, $subject, $text);
    }
}
