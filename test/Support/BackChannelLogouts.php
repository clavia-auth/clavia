<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support;

use Clavia\Adapter\Secondary\System\AfterResponseTasks;
use Clavia\Application\Oidc\CompactJws;
use Clavia\Application\Oidc\Logout\BackChannelLogout;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Oidc\SigningAlgorithm;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\SecretGenerator;
use ClaviaTest\Support\Fake\InMemorySigningKeys;
use ClaviaTest\Support\Fake\RecordingBackChannelDelivery;
use ClaviaTest\Support\Fake\SeededRandomSource;
use Psr\Log\NullLogger;

/**
 * A {@see BackChannelLogout} for unit tests: real tokens, signed by an in-memory key,
 * delivered to a recording fake once the test runs the deferred tasks.
 */
final class BackChannelLogouts
{
    public const string ISSUER = 'https://auth.clavia.test';

    private function __construct()
    {
    }

    /**
     * @return array{BackChannelLogout, AfterResponseTasks, RecordingBackChannelDelivery}
     */
    public static function for(ClientRepository $clients, Clock $clock): array
    {
        $keys = new InMemorySigningKeys($clock);
        $keys->create(SigningAlgorithm::RS256, $clock->now());
        $tasks = new AfterResponseTasks(new NullLogger());
        $delivery = new RecordingBackChannelDelivery();

        return [
            new BackChannelLogout(
                $clients,
                $keys,
                new CompactJws($keys),
                $delivery,
                $tasks,
                new SecretGenerator(new SeededRandomSource(77)),
                $clock,
                self::ISSUER,
                120,
            ),
            $tasks,
            $delivery,
        ];
    }
}
