<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Webhook;

/**
 * The `webhook-signature` header of the Standard Webhooks specification: `v1,` and the base64 of
 * HMAC-SHA256, keyed with the secret's bytes, over `<webhook-id>.<webhook-timestamp>.<body>`; one
 * signature per secret, space-separated, so during a rotation a receiver holding either secret
 * verifies (docs/design/webhooks.md §2).
 */
final readonly class StandardWebhookSignature
{
    private function __construct()
    {
    }

    /** @param non-empty-list<WebhookSecret> $secrets The current one first. */
    public static function header(string $id, int $timestamp, string $body, array $secrets): string
    {
        $content = $id . '.' . $timestamp . '.' . $body;

        return implode(' ', array_map(
            static fn (WebhookSecret $secret): string
                => 'v1,' . base64_encode(hash_hmac('sha256', $content, $secret->key(), true)),
            $secrets,
        ));
    }
}
