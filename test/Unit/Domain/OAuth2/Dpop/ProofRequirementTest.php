<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Domain\OAuth2\Dpop;

use Clavia\Domain\OAuth2\Dpop\DpopAlgorithm;
use Clavia\Domain\OAuth2\Dpop\DpopProof;
use Clavia\Domain\OAuth2\Dpop\DpopRefusal;
use Clavia\Domain\OAuth2\Dpop\JwkThumbprint;
use Clavia\Domain\OAuth2\Dpop\ProofRequirement;
use Clavia\Domain\Shared\InvalidValue;
use DateTimeImmutable;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The rules of RFC 9449 §4.3 that are not cryptography.
 */
final class ProofRequirementTest extends TestCase
{
    private const string URL = 'https://auth.clavia.test/oauth2/token';
    private const string KEY = 'NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs';
    private const string OTHER_KEY = 'AzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs';

    public function testAProofForThisRequestPasses(): void
    {
        self::assertNull(self::requirement()->check(self::proof(), self::now(), 60));
    }

    /** @return iterable<string, array{string}> */
    public static function sameResource(): iterable
    {
        yield 'case in scheme and host' => ['HTTPS://Auth.Clavia.TEST/oauth2/token'];
        yield 'the default port written' => ['https://auth.clavia.test:443/oauth2/token'];
        yield 'a percent-encoded unreserved character' => ['https://auth.clavia.test/oauth2/%74oken'];
        yield 'a query, which is not compared' => ['https://auth.clavia.test/oauth2/token?x=1'];
    }

    #[DataProvider('sameResource')]
    public function testTheUrlIsComparedNormalised(string $url): void
    {
        self::assertNull(self::requirement()->check(self::proof(url: $url), self::now(), 60));
    }

    /** @return iterable<string, array{DpopProof, DpopRefusal}> */
    public static function refusals(): iterable
    {
        yield 'another method' => [self::proof(method: 'GET'), DpopRefusal::WrongMethod];
        yield 'the method in lower case' => [self::proof(method: 'post'), DpopRefusal::WrongMethod];
        yield 'another path' => [self::proof(url: 'https://auth.clavia.test/oauth2/par'), DpopRefusal::WrongUrl];
        yield 'another host' => [self::proof(url: 'https://evil.test/oauth2/token'), DpopRefusal::WrongUrl];
        yield 'plain http' => [self::proof(url: 'http://auth.clavia.test/oauth2/token'), DpopRefusal::WrongUrl];
        yield 'another port' => [self::proof(url: 'https://auth.clavia.test:8443/oauth2/token'), DpopRefusal::WrongUrl];
        yield 'not a URL' => [self::proof(url: 'not a url'), DpopRefusal::WrongUrl];
        yield 'older than its lifetime' => [self::proof(issuedAt: '2026-01-15T09:58:59Z'), DpopRefusal::TooOld];
        yield 'from the future' => [self::proof(issuedAt: '2026-01-15T10:00:06Z'), DpopRefusal::FromTheFuture];
    }

    #[DataProvider('refusals')]
    public function testEachRuleRefusesForItsReason(DpopProof $proof, DpopRefusal $reason): void
    {
        self::assertSame($reason, self::requirement()->check($proof, self::now(), 60));
    }

    public function testTheEdgesOfTheWindowAreIn(): void
    {
        self::assertNull(self::requirement()->check(self::proof(issuedAt: '2026-01-15T09:59:00Z'), self::now(), 60));
        self::assertNull(self::requirement()->check(self::proof(issuedAt: '2026-01-15T10:00:05Z'), self::now(), 60));
    }

    public function testWithATokenThePresentedHashAndTheBoundKeyMustMatch(): void
    {
        $requirement = new ProofRequirement('POST', self::URL, 'the-token', JwkThumbprint::fromString(self::KEY));
        $ath = ProofRequirement::hashOf('the-token');

        self::assertNull($requirement->check(self::proof(ath: $ath), self::now(), 60));
        self::assertSame(DpopRefusal::WrongAccessToken, $requirement->check(self::proof(), self::now(), 60));
        self::assertSame(
            DpopRefusal::WrongAccessToken,
            $requirement->check(self::proof(ath: ProofRequirement::hashOf('another')), self::now(), 60),
        );
        self::assertSame(
            DpopRefusal::WrongKey,
            $requirement->check(self::proof(ath: $ath, key: self::OTHER_KEY), self::now(), 60),
        );
    }

    public function testAThumbprintIsADigest(): void
    {
        $this->expectException(InvalidValue::class);

        JwkThumbprint::fromString('short');
    }

    private static function requirement(): ProofRequirement
    {
        return new ProofRequirement('POST', self::URL);
    }

    private static function now(): DateTimeImmutable
    {
        return new DateTimeImmutable('2026-01-15T10:00:00Z');
    }

    /**
     * @param non-empty-string|null $ath
     */
    private static function proof(
        string $method = 'POST',
        string $url = self::URL,
        string $issuedAt = '2026-01-15T10:00:00Z',
        ?string $ath = null,
        string $key = self::KEY,
    ): DpopProof {
        return new DpopProof(
            JwkThumbprint::fromString($key),
            DpopAlgorithm::ES256,
            $method === '' ? 'POST' : $method,
            $url === '' ? self::URL : $url,
            new DateTimeImmutable($issuedAt),
            'jti-1',
            $ath,
        );
    }
}
