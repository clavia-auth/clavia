<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);


namespace ClaviaTest\Integration\Redis;

use Clavia\Adapter\Secondary\Redis\RedisConnection;
use Clavia\Adapter\Secondary\Redis\RedisMailOutbox;
use Clavia\Application\Port\OutgoingMail;
use ClaviaTest\Support\IntegrationTestCase;
use ClaviaTest\Support\TestEnvironment;

final class RedisMailOutboxTest extends IntegrationTestCase
{
    public function testTheOutboxKeepsTheLastFiftyNewestFirst(): void
    {
        $outbox = new RedisMailOutbox(new RedisConnection(TestEnvironment::redisUrl()));
        for ($i = 1; $i <= 55; ++$i) {
            $outbox->record(new OutgoingMail('jane@example.com', 'Message ' . $i, "Line one\nLine é/" . $i));
        }

        $recent = $outbox->recent(3);

        self::assertSame(['Message 55', 'Message 54', 'Message 53'], array_map(
            static fn (OutgoingMail $mail): string => $mail->subject,
            $recent,
        ));
        self::assertSame("Line one\nLine é/55", $recent[0]->text);
        self::assertCount(50, $outbox->recent(200));
        self::assertSame(50, $this->redis()->lLen('mail-outbox'));
    }

    public function testAnEntryThatCannotBeReadIsSkipped(): void
    {
        $outbox = new RedisMailOutbox(new RedisConnection(TestEnvironment::redisUrl()));
        $outbox->record(new OutgoingMail('jane@example.com', 'Kept', 'text'));
        $this->redis()->lPush('mail-outbox', '{', '{"to":"","subject":"x","text":""}');

        self::assertSame(['Kept'], array_map(
            static fn (OutgoingMail $mail): string => $mail->subject,
            $outbox->recent(10),
        ));
    }
}
