<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Management\Webhooks;

use Clavia\Application\Port\SecretCipher;
use Clavia\Domain\Shared\RandomSource;
use Clavia\Domain\Webhook\WebhookEndpointId;
use Clavia\Domain\Webhook\WebhookSecret;

/**
 * Makes an endpoint's secret and seals it, with the endpoint's id in the associated data
 * (`webhook:<id>:secret`), so a seal copied onto another endpoint does not open there.
 */
final readonly class WebhookSecrets
{
    public function __construct(
        private RandomSource $random,
        private SecretCipher $cipher,
    ) {
    }

    public function generate(): WebhookSecret
    {
        return WebhookSecret::generate($this->random);
    }

    /** @return non-empty-string */
    public function seal(WebhookEndpointId $id, WebhookSecret $secret): string
    {
        return $this->cipher->encrypt($secret->reveal(), self::context($id));
    }

    public static function context(WebhookEndpointId $id): string
    {
        return 'webhook:' . $id->value . ':secret';
    }
}
