<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Integration\Authorization;

use Clavia\Adapter\Secondary\Authorization\OpenFgaDecisionEngine;
use Clavia\Application\Port\DecisionEngine;
use ClaviaTest\Support\Contract\DecisionEngineContract;
use ClaviaTest\Support\RecordingLogger;
use ClaviaTest\Support\TestEnvironment;
use GuzzleHttp\Client;
use GuzzleHttp\RequestOptions;
use Laminas\Diactoros\RequestFactory;
use Laminas\Diactoros\StreamFactory;

/**
 * The decision engine contract against a real OpenFGA (docker-compose.yml's `openfga`), skipped
 * when `CLAVIA_TEST_FGA_URL` names none.
 */
final class OpenFgaDecisionEngineTest extends DecisionEngineContract
{
    private ?DecisionEngine $engine = null;

    #[\Override]
    protected function setUp(): void
    {
        if (TestEnvironment::fgaUrl() === null) {
            self::markTestSkipped('CLAVIA_TEST_FGA_URL names no OpenFGA to run the contract against.');
        }
    }

    #[\Override]
    protected function engine(): DecisionEngine
    {
        return $this->engine ??= self::at((string) TestEnvironment::fgaUrl());
    }

    #[\Override]
    protected function unreachableEngine(): DecisionEngine
    {
        // Nothing listens on port 1.
        return self::at('http://127.0.0.1:1');
    }

    private static function at(string $url): DecisionEngine
    {
        return new OpenFgaDecisionEngine(
            new Client([
                RequestOptions::CONNECT_TIMEOUT => 2.0,
                RequestOptions::TIMEOUT => 5.0,
                RequestOptions::ALLOW_REDIRECTS => false,
                RequestOptions::HTTP_ERRORS => false,
            ]),
            new RequestFactory(),
            new StreamFactory(),
            $url,
            TestEnvironment::fgaApiKey(),
            new RecordingLogger(),
        );
    }
}
