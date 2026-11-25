<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Connection\Saml;

use Clavia\Application\Port\DomainEvents;
use Clavia\Application\Port\Saml\ServiceProviderKeyStore;
use Clavia\Application\Port\TransactionManager;
use Clavia\Domain\Connection\Saml\Event\ServiceProviderKeysGenerated;
use Clavia\Domain\Connection\Saml\Event\ServiceProviderKeysRotated;
use Clavia\Domain\Connection\Saml\ServiceProviderKeyStatus;
use Clavia\Domain\Connection\Saml\ServiceProviderKeyUsage;
use Clavia\Domain\Shared\Clock;
use LogicException;

/**
 * `clavia saml-keys:rotate` and `POST /api/v1/saml-keys/rotate` (§5.1): one step each time, the
 * rollover Shibboleth documents for service providers. An identity provider picks up a certificate
 * when it reads the metadata, which is rarely at once, so a new pair is **published** first, as next,
 * and **promoted** only once it has been published for `CLAVIA_SAML_KEY_OVERLAP_DAYS`:
 *
 * - no keys: the first pair, current;
 * - no next pair: one is introduced;
 * - a next pair inside its overlap: nothing, and when it will be promoted;
 * - a next pair past it: promoted; the current pair retired (no longer published; the encryption key
 *   still decrypts what an identity provider that has not moved still sends).
 *
 * And at every step, retired keys whose overlap is over are deleted. All of it under a lock on the
 * keys, so two rotations at once cannot both act.
 */
final readonly class RotateServiceProviderKeys
{
    /** @param positive-int $overlapDays */
    public function __construct(
        private ServiceProviderKeyStore $keys,
        private TransactionManager $transactions,
        private Clock $clock,
        private int $overlapDays,
        private DomainEvents $events,
    ) {
    }

    public function __invoke(): ServiceProviderKeyRotation
    {
        /** @var ServiceProviderKeyRotation */
        return $this->transactions->transactional(function (): ServiceProviderKeyRotation {
            $now = $this->clock->now();
            $overlap = sprintf('%d days', $this->overlapDays);
            $set = $this->keys->lockAll();

            $deleted = [];
            foreach ($set->retiredBefore($now->modify('-' . $overlap)) as $expired) {
                $this->keys->delete($expired->kid);
                $deleted[] = $expired->kid;
            }

            $current = $set->current(ServiceProviderKeyUsage::Signing);
            $next = $set->next(ServiceProviderKeyUsage::Signing);
            if ($current === null && $next === null) {
                $pair = $this->keys->createPair(ServiceProviderKeyStatus::Current, $now);
                $this->events->dispatch(new ServiceProviderKeysGenerated($pair['signing'], $pair['encryption']));

                return new ServiceProviderKeyRotation(RotationStep::Generated, null, $this->keys->all(), $deleted);
            }
            if ($next === null) {
                $pair = $this->keys->createPair(ServiceProviderKeyStatus::Next, $now);
                $this->events->dispatch(new ServiceProviderKeysRotated($pair['signing'], $pair['encryption'], false));

                return new ServiceProviderKeyRotation(
                    RotationStep::Introduced,
                    $now->modify('+' . $overlap),
                    $this->keys->all(),
                    $deleted,
                );
            }
            $promotesAt = $next->createdAt->modify('+' . $overlap);
            if ($promotesAt > $now) {
                return new ServiceProviderKeyRotation(RotationStep::Waiting, $promotesAt, $this->keys->all(), $deleted);
            }

            foreach (ServiceProviderKeyUsage::cases() as $usage) {
                $outgoing = $set->current($usage);
                if ($outgoing !== null) {
                    $this->keys->save($outgoing->retired($now));
                }
            }
            $promoted = [];
            foreach (ServiceProviderKeyUsage::cases() as $usage) {
                $incoming = $set->next($usage)
                    ?? throw new LogicException('A next pair lacks its ' . $usage->value . ' key.');
                $promoted[$usage->value] = $incoming->promoted($now);
                $this->keys->save($promoted[$usage->value]);
            }
            $this->events->dispatch(
                new ServiceProviderKeysRotated($promoted['signing'], $promoted['encryption'], true),
            );

            return new ServiceProviderKeyRotation(RotationStep::Promoted, null, $this->keys->all(), $deleted);
        });
    }
}
