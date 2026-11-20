<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Unit\Domain\Oidc;

use Clavia\Domain\Oidc\SigningAlgorithm;
use PHPUnit\Framework\TestCase;

final class SigningAlgorithmTest extends TestCase
{
    public function testRs256IsAnRsaKeyHashingWithSha256(): void
    {
        self::assertSame('RSA', SigningAlgorithm::RS256->keyType());
        self::assertSame('sha256', SigningAlgorithm::RS256->hashAlgorithm());
    }

    public function testTheHalfHashIsTheLeftHalfOfTheDigestBase64UrlEncoded(): void
    {
        // OIDC Core Appendix A.3: this access token, and the `at_hash` of the ID token issued with it.
        self::assertSame(
            '77QmUPtjPfzWtF2AnpK9RQ',
            SigningAlgorithm::RS256->halfHash('jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y'),
        );
    }
}
