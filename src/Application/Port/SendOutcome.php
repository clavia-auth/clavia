<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Port;

use Clavia\Domain\Webhook\DeliveryFailure;

/**
 * What became of one attempt: a status code if it was answered, how long it took, why it failed.
 * Which statuses are a success is the sender's to say: the application holds no status code.
 */
final readonly class SendOutcome
{
    private function __construct(
        public ?int $statusCode,
        public int $durationMs,
        public ?DeliveryFailure $failure,
    ) {
    }

    /** A 2xx: delivered. */
    public static function accepted(int $statusCode, int $durationMs): self
    {
        return new self($statusCode, $durationMs, null);
    }

    /** Answered with anything else. */
    public static function refused(int $statusCode, int $durationMs): self
    {
        return new self($statusCode, $durationMs, DeliveryFailure::Status);
    }

    /** Not answered: unreachable, or a URL the policy refuses now. */
    public static function unsent(DeliveryFailure $why, int $durationMs): self
    {
        return new self(null, $durationMs, $why);
    }
}
