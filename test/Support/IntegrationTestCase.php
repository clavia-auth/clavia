<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\Support;

use Clavia\Adapter\Secondary\Persistence\PhpDb\Database;
use Clavia\Adapter\Secondary\Persistence\PhpDb\PostgresUrl;
use PHPUnit\Framework\TestCase;
use Redis;

/**
 * Base for tests of one secondary adapter against the real PostgreSQL or Redis.
 *
 * Tests that need tables of their own get a scratch schema: a PostgreSQL schema created
 * for the test and dropped after it, so nothing they create can leak into the
 * application's tables or into another test.
 */
abstract class IntegrationTestCase extends TestCase
{
    private ?string $scratchSchema = null;

    /** @var list<Database> */
    private array $scratchConnections = [];

    #[\Override]
    protected function setUp(): void
    {
        TestStorage::reset();
    }

    #[\Override]
    protected function tearDown(): void
    {
        foreach ($this->scratchConnections as $connection) {
            if ($connection->inTransaction()) {
                $connection->rollBack();
            }
        }
        $this->scratchConnections = [];

        if ($this->scratchSchema !== null) {
            TestStorage::database()->executeScript(sprintf('DROP SCHEMA IF EXISTS %s CASCADE', $this->scratchSchema));
            $this->scratchSchema = null;
        }
    }

    protected function redis(): Redis
    {
        return TestStorage::redis();
    }

    /**
     * A new connection whose tables live in this test's scratch schema. Call it twice to
     * get two independent sessions looking at the same tables — what a locking test needs.
     */
    protected function scratchConnection(): Database
    {
        if ($this->scratchSchema === null) {
            $this->scratchSchema = 'scratch_' . bin2hex(random_bytes(6));
            TestStorage::database()->executeScript(sprintf('CREATE SCHEMA %s', $this->scratchSchema));
        }

        $url = TestEnvironment::databaseUrl()
            . (str_contains(TestEnvironment::databaseUrl(), '?') ? '&' : '?')
            . 'options=' . rawurlencode('-c search_path=' . $this->scratchSchema);

        return $this->scratchConnections[] = new Database(PostgresUrl::parse($url));
    }
}
