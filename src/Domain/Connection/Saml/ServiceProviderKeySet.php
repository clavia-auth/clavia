<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Connection\Saml;

use Clavia\Domain\Shared\InvalidValue;
use DateTimeImmutable;

/**
 * Every service provider key, with the rule the database enforces too: at most one current and one
 * next per usage. A pair is a signing key and an encryption key with the same status.
 */
final readonly class ServiceProviderKeySet
{
    /** @param list<ServiceProviderKey> $keys */
    private function __construct(public array $keys)
    {
    }

    /**
     * @param list<ServiceProviderKey> $keys
     *
     * @throws InvalidValue
     */
    public static function of(array $keys): self
    {
        $seen = [];
        foreach ($keys as $key) {
            if ($key->status === ServiceProviderKeyStatus::Retired) {
                continue;
            }
            $slot = $key->usage->value . ':' . $key->status->value;
            if (isset($seen[$slot])) {
                throw new InvalidValue(sprintf('Two %s keys are %s.', $key->usage->value, $key->status->value));
            }
            $seen[$slot] = true;
        }
        usort($keys, static fn (ServiceProviderKey $a, ServiceProviderKey $b): int
            => [self::rank($a), $b->createdAt, $a->usage->value] <=> [self::rank($b), $a->createdAt, $b->usage->value]);

        return new self($keys);
    }

    public static function none(): self
    {
        return new self([]);
    }

    public function current(ServiceProviderKeyUsage $usage): ?ServiceProviderKey
    {
        return $this->find($usage, ServiceProviderKeyStatus::Current);
    }

    public function next(ServiceProviderKeyUsage $usage): ?ServiceProviderKey
    {
        return $this->find($usage, ServiceProviderKeyStatus::Next);
    }

    public function byKid(string $kid): ?ServiceProviderKey
    {
        foreach ($this->keys as $key) {
            if ($key->kid === $kid) {
                return $key;
            }
        }

        return null;
    }

    /** What the metadata publishes: the current keys, then the next ones. */
    public function published(): self
    {
        return new self(array_values(array_filter(
            $this->keys,
            static fn (ServiceProviderKey $key): bool => $key->isPublished(),
        )));
    }

    /** @return list<ServiceProviderKey> Retired before `$before`: due for deletion. */
    public function retiredBefore(DateTimeImmutable $before): array
    {
        return array_values(array_filter(
            $this->keys,
            static fn (ServiceProviderKey $key): bool => $key->retiredAt !== null && $key->retiredAt < $before,
        ));
    }

    public function isEmpty(): bool
    {
        return $this->keys === [];
    }

    private function find(ServiceProviderKeyUsage $usage, ServiceProviderKeyStatus $status): ?ServiceProviderKey
    {
        foreach ($this->keys as $key) {
            if ($key->usage === $usage && $key->status === $status) {
                return $key;
            }
        }

        return null;
    }

    private static function rank(ServiceProviderKey $key): int
    {
        return match ($key->status) {
            ServiceProviderKeyStatus::Current => 0,
            ServiceProviderKeyStatus::Next => 1,
            ServiceProviderKeyStatus::Retired => 2,
        };
    }
}
