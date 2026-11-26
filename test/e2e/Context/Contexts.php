<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace ClaviaTest\E2e\Context;

use Behat\Behat\Context\Context;
use Behat\Behat\Context\Environment\InitializedContextEnvironment;
use Behat\Behat\Hook\Scope\BeforeScenarioScope;
use RuntimeException;

/** The other contexts of the scenario being run, which a context asks for to share what it holds. */
final class Contexts
{
    /**
     * @template T of Context
     * @param class-string<T> $class
     * @return T
     */
    public static function of(BeforeScenarioScope $scope, string $class): Context
    {
        $environment = $scope->getEnvironment();
        if (! $environment instanceof InitializedContextEnvironment) {
            throw new RuntimeException('The scenario has no contexts.');
        }
        /** @var T $context getContext() throws for a context the suite does not list */
        $context = $environment->getContext($class);

        return $context;
    }
}
