<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Application\Oidc;

use Clavia\Application\Oidc\Keys\GenerateSigningKey;
use Clavia\Application\Oidc\Keys\ListSigningKeys;
use Clavia\Application\Oidc\Keys\PublishSigningKeys;
use Clavia\Application\Oidc\Keys\RotateSigningKey;
use Clavia\Application\Oidc\Keys\SigningKeyAlreadyActive;
use Clavia\Domain\Oidc\Event\SigningKeyCreated;
use Clavia\Domain\Oidc\Event\SigningKeyRotated;
use Clavia\Domain\Oidc\PublicJwk;
use Clavia\Domain\Oidc\SigningAlgorithm;
use ClaviaTest\Support\Fake\FrozenClock;
use ClaviaTest\Support\Fake\InMemoryDomainEvents;
use ClaviaTest\Support\Fake\InMemorySigningKeys;
use ClaviaTest\Support\Fake\InMemoryTransactionManager;
use PHPUnit\Framework\TestCase;

final class SigningKeyLifecycleTest extends TestCase
{
    private const int GRACE = 7200;

    private FrozenClock $clock;
    private InMemorySigningKeys $keys;
    private InMemoryDomainEvents $events;

    #[\Override]
    protected function setUp(): void
    {
        $this->clock = new FrozenClock('2026-01-15T10:00:00Z');
        $this->keys = new InMemorySigningKeys($this->clock);
        $this->events = new InMemoryDomainEvents();
    }

    public function testTheFirstKeyIsGeneratedActive(): void
    {
        $key = $this->generate()();

        self::assertTrue($key->isActive());
        self::assertSame($key->kid(), $this->keys->activeKey()->kid);
    }

    public function testGeneratingIsRefusedOnceAKeyIsActive(): void
    {
        $first = $this->generate()();

        try {
            $this->generate()();
            self::fail('A second key was generated.');
        } catch (SigningKeyAlreadyActive $refusal) {
            self::assertStringContainsString($first->kid(), $refusal->getMessage());
            self::assertStringContainsString('clavia keys:rotate', $refusal->getMessage());
        }

        self::assertCount(1, $this->keys->all());
    }

    public function testRotationRetiresTheActiveKeyWithItsGraceAndActivatesANewOne(): void
    {
        $old = $this->generate()();

        $rotation = $this->rotate()();

        self::assertNotSame($old->kid(), $rotation->active->kid());
        self::assertSame($rotation->active->kid(), $this->keys->activeKey()->kid);
        self::assertSame($old->kid(), $rotation->retired?->kid());
        self::assertEquals($this->clock->now()->modify('+7200 seconds'), $rotation->retired?->publishedUntil());
        self::assertSame(
            [$rotation->active->kid(), $old->kid()],
            array_map(static fn (PublicJwk $jwk): string => $jwk->kid, new PublishSigningKeys($this->keys)()),
        );
    }

    public function testGeneratingAndRotatingSayWhichKeysTookOver(): void
    {
        $old = $this->generate()();

        $rotation = $this->rotate()();

        self::assertSame($old->kid(), $this->events->ofType(SigningKeyCreated::class)[0]->key->kid());
        $rotated = $this->events->ofType(SigningKeyRotated::class)[0];
        self::assertSame($rotation->active->kid(), $rotated->active->kid());
        self::assertSame($old->kid(), $rotated->retired?->kid());
    }

    public function testRotatingWithNoActiveKeySimplyCreatesOne(): void
    {
        $rotation = $this->rotate()();

        self::assertNull($rotation->retired);
        self::assertSame($rotation->active->kid(), $this->keys->activeKey()->kid);
    }

    public function testTheListingSaysWhichKeysAreStillPublished(): void
    {
        $first = $this->generate()();
        $this->rotate()();
        $this->clock->advance(self::GRACE);
        $this->rotate()();

        $listed = new ListSigningKeys($this->keys, $this->clock)();

        self::assertCount(3, $listed);
        self::assertSame([true, true, false], array_map(static fn ($entry): bool => $entry->published, $listed));
        self::assertSame($first->kid(), $listed[2]->key->kid());
    }

    public function testTheGraceOutlastsEveryTokenTwiceOverPlusADay(): void
    {
        self::assertSame(3600 * 2 + 86_400, RotateSigningKey::grace(3600));
    }

    private function generate(): GenerateSigningKey
    {
        return new GenerateSigningKey(
            $this->keys,
            new InMemoryTransactionManager(),
            $this->clock,
            SigningAlgorithm::RS256,
            $this->events,
        );
    }

    private function rotate(): RotateSigningKey
    {
        return new RotateSigningKey(
            $this->keys,
            new InMemoryTransactionManager(),
            $this->clock,
            SigningAlgorithm::RS256,
            self::GRACE,
            $this->events,
        );
    }
}
