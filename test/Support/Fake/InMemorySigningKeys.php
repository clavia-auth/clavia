<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support\Fake;

use Clavia\Application\Port\NoActiveSigningKey;
use Clavia\Application\Port\SigningFailed;
use Clavia\Application\Port\SigningKeyReference;
use Clavia\Application\Port\SigningKeyStore;
use Clavia\Application\Port\TokenSigner;
use Clavia\Domain\Oidc\SigningAlgorithm;
use Clavia\Domain\Oidc\SigningKey;
use Clavia\Domain\Shared\Clock;
use ClaviaTest\Support\TestSigningKeys;
use DateTimeImmutable;
use LogicException;

/**
 * An in-memory signing backend: the key store and the signer together, as the
 * `postgres` backend is, with real RSA keys from {@see TestSigningKeys} so that what it
 * signs verifies.
 *
 * It keeps the backend's rules: at most one active key, only the active key signs, and
 * only published keys are listed.
 */
final class InMemorySigningKeys implements SigningKeyStore, TokenSigner
{
    /** @var array<string, array{key: SigningKey, index: int}> By kid, in creation order. */
    private array $keys = [];

    private int $next = 0;

    public function __construct(private readonly Clock $clock)
    {
    }

    #[\Override]
    public function create(SigningAlgorithm $algorithm, DateTimeImmutable $now): SigningKey
    {
        foreach ($this->keys as $entry) {
            if ($entry['key']->isActive()) {
                throw new LogicException('A second active signing key: retire the first one before creating one.');
            }
        }

        $index = $this->next++;
        $key = SigningKey::activate(TestSigningKeys::publicJwk($index, $algorithm), $now);
        $this->keys[$key->kid()] = ['key' => clone $key, 'index' => $index];

        return $key;
    }

    #[\Override]
    public function lockActive(): ?SigningKey
    {
        foreach ($this->keys as $entry) {
            if ($entry['key']->isActive()) {
                return clone $entry['key'];
            }
        }

        return null;
    }

    #[\Override]
    public function save(SigningKey $key): void
    {
        if (isset($this->keys[$key->kid()])) {
            $this->keys[$key->kid()]['key'] = clone $key;
        }
    }

    #[\Override]
    public function all(): array
    {
        $keys = array_reverse(
            array_map(static fn (array $entry): SigningKey => clone $entry['key'], array_values($this->keys)),
        );
        // Stable: among keys of the same standing, the newest stays first.
        usort($keys, static fn (SigningKey $a, SigningKey $b): int => $b->isActive() <=> $a->isActive());

        return $keys;
    }

    #[\Override]
    public function activeKey(): SigningKeyReference
    {
        $active = $this->lockActive() ?? throw NoActiveSigningKey::create();

        return new SigningKeyReference($active->kid(), $active->algorithm());
    }

    #[\Override]
    public function sign(SigningKeyReference $key, string $signingInput): string
    {
        $entry = $this->keys[$key->kid] ?? null;
        if ($entry === null || ! $entry['key']->isActive() || $entry['key']->algorithm() !== $key->algorithm) {
            throw new SigningFailed(sprintf('Signing key %s is not the active key.', $key->kid));
        }

        openssl_sign($signingInput, $signature, TestSigningKeys::privateKey($entry['index']), OPENSSL_ALGO_SHA256);
        assert($signature !== '');

        return $signature;
    }

    #[\Override]
    public function publicKeys(): array
    {
        $now = $this->clock->now();

        $published = [];
        foreach ($this->all() as $key) {
            if ($key->isPublishedAt($now)) {
                $published[] = $key->publicJwk;
            }
        }

        return $published;
    }
}
