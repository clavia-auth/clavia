<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Application\Port\SendOutcome;
use Clavia\Application\Port\WebhookSender;
use Clavia\Domain\Shared\Url;

/** Records what it is asked to send, and answers what it is told (a 200 by default). */
final class FakeWebhookSender implements WebhookSender
{
    /** @var list<array{url: string, headers: array<string, string>, body: string}> */
    public array $sent = [];

    /** @var list<SendOutcome> Answers in turn; once exhausted, a 200. */
    public array $answers = [];

    #[\Override]
    public function send(Url $url, array $headers, string $body): SendOutcome
    {
        $this->sent[] = ['url' => $url->value, 'headers' => $headers, 'body' => $body];

        return array_shift($this->answers) ?? SendOutcome::accepted(200, 12);
    }
}
