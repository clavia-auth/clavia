<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Webhook;

use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\Url;
use DateTimeImmutable;

/**
 * An https URL that receives the audit events it subscribes to, signed (docs/design/webhooks.md).
 * It holds its secrets sealed: the current one, and for {@see ROTATION_OVERLAP_SECONDS} after a
 * rotation the previous one, so a receiver can switch without missing a delivery. What a seal
 * holds is the application's to open; the endpoint never sees a secret.
 */
final readonly class WebhookEndpoint
{
    public const int MAX_ENDPOINTS = 20;
    public const int MAX_DESCRIPTION_LENGTH = 120;
    public const int ROTATION_OVERLAP_SECONDS = 86_400;

    /** An endpoint every delivery to which has failed this long is switched off (§2, "A dead endpoint"). */
    public const int DEAD_AFTER_DAYS = 5;

    /**
     * @param non-empty-string      $sealedSecret
     * @param non-empty-string|null $sealedPreviousSecret
     */
    private function __construct(
        public WebhookEndpointId $id,
        public Url $url,
        public string $description,
        public EventFilter $events,
        public bool $isEnabled,
        public string $sealedSecret,
        public ?string $sealedPreviousSecret,
        public ?DateTimeImmutable $previousSecretUntil,
        public DateTimeImmutable $createdAt,
        public DateTimeImmutable $updatedAt,
        public ?DateTimeImmutable $failingSince = null,
        public ?WebhookDisabledReason $disabledReason = null,
    ) {
    }

    /**
     * @param non-empty-string $sealedSecret
     *
     * @throws InvalidValue
     */
    public static function register(
        WebhookEndpointId $id,
        Url $url,
        string $description,
        EventFilter $events,
        string $sealedSecret,
        DateTimeImmutable $now,
    ): self {
        return new self(
            $id,
            self::checkedUrl($url),
            self::checkedDescription($description),
            $events,
            true,
            $sealedSecret,
            null,
            null,
            $now,
            $now,
        );
    }

    /**
     * Rebuild an endpoint from storage.
     *
     * @param non-empty-string      $sealedSecret
     * @param non-empty-string|null $sealedPreviousSecret
     */
    public static function reconstitute(
        WebhookEndpointId $id,
        Url $url,
        string $description,
        EventFilter $events,
        bool $isEnabled,
        string $sealedSecret,
        ?string $sealedPreviousSecret,
        ?DateTimeImmutable $previousSecretUntil,
        DateTimeImmutable $createdAt,
        DateTimeImmutable $updatedAt,
        ?DateTimeImmutable $failingSince = null,
        ?WebhookDisabledReason $disabledReason = null,
    ): self {
        return new self(
            $id,
            $url,
            $description,
            $events,
            $isEnabled,
            $sealedSecret,
            $sealedPreviousSecret,
            $previousSecretUntil,
            $createdAt,
            $updatedAt,
            $failingSince,
            $isEnabled ? null : ($disabledReason ?? WebhookDisabledReason::Operator),
        );
    }

    /** @throws InvalidValue */
    public function sendingTo(Url $url, DateTimeImmutable $now): self
    {
        return clone($this, ['url' => self::checkedUrl($url), 'updatedAt' => $now]);
    }

    /** @throws InvalidValue */
    public function described(string $description, DateTimeImmutable $now): self
    {
        return clone($this, ['description' => self::checkedDescription($description), 'updatedAt' => $now]);
    }

    public function listeningTo(EventFilter $events, DateTimeImmutable $now): self
    {
        return clone($this, ['events' => $events, 'updatedAt' => $now]);
    }

    /**
     * Switched on or off by an operator. Switching it on forgets why it was off and how long it had
     * been failing: it is given five days again.
     */
    public function enabled(bool $enabled, DateTimeImmutable $now): self
    {
        if ($enabled === $this->isEnabled) {
            return clone($this, ['updatedAt' => $now]);
        }

        return clone($this, [
            'isEnabled' => $enabled,
            'failingSince' => null,
            'disabledReason' => $enabled ? null : WebhookDisabledReason::Operator,
            'updatedAt' => $now,
        ]);
    }

    /** The instant before which a first failure, never followed by a success, makes it dead. */
    public static function deadIfFailingBefore(DateTimeImmutable $now): DateTimeImmutable
    {
        return $now->modify(sprintf('-%d days', self::DEAD_AFTER_DAYS));
    }

    /**
     * A new secret signs from now on; the one it replaces signs beside it for a day.
     *
     * @param non-empty-string $sealedSecret
     */
    public function rotatedTo(string $sealedSecret, DateTimeImmutable $now): self
    {
        return clone($this, [
            'sealedSecret' => $sealedSecret,
            'sealedPreviousSecret' => $this->sealedSecret,
            'previousSecretUntil' => $now->modify(sprintf('+%d seconds', self::ROTATION_OVERLAP_SECONDS)),
            'updatedAt' => $now,
        ]);
    }

    /**
     * The previous secret's seal while it still signs; null once its day is over.
     *
     * @return non-empty-string|null
     */
    public function previousSecretAt(DateTimeImmutable $now): ?string
    {
        return $this->previousSecretUntil !== null && $now < $this->previousSecretUntil
            ? $this->sealedPreviousSecret
            : null;
    }

    /** @throws InvalidValue */
    private static function checkedUrl(Url $url): Url
    {
        if (! $url->isHttps() || $url->hasFragment()) {
            throw new InvalidValue('A webhook endpoint is an https URL without a fragment.');
        }

        return $url;
    }

    /** @throws InvalidValue */
    private static function checkedDescription(string $description): string
    {
        if (
            ! mb_check_encoding($description, 'UTF-8')
            || mb_strlen($description, 'UTF-8') > self::MAX_DESCRIPTION_LENGTH
            || preg_match('/[\x00-\x1F\x7F]/', $description) === 1
        ) {
            throw new InvalidValue(sprintf(
                'A webhook description is at most %d characters on one line.',
                self::MAX_DESCRIPTION_LENGTH,
            ));
        }

        return $description;
    }
}
