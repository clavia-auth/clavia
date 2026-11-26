<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

use Behat\Config\Config;
use Behat\Config\Formatter\JUnitFormatter;
use Behat\Config\Formatter\PrettyFormatter;
use Behat\Config\Profile;
use Behat\Config\Suite;
use ClaviaTest\E2e\Context\AccountContext;
use ClaviaTest\E2e\Context\HttpContext;
use ClaviaTest\E2e\Context\MailContext;
use ClaviaTest\E2e\Context\ManagementContext;
use ClaviaTest\E2e\Context\RefreshContext;
use ClaviaTest\E2e\Context\SignInContext;

// The end-to-end scenarios (docs/design/end-to-end-scenarios.md): HTTP, from outside, against the
// stack of test/e2e. `test/e2e/up.sh` first, then `composer e2e`.
return new Config()
    ->withProfile(
        new Profile('default')
            ->withFormatter(new PrettyFormatter())
            // A file CI keeps when a scenario fails.
            ->withFormatter(new JUnitFormatter()->withOutputPath(__DIR__ . '/build/behat'))
            ->withSuite(
                new Suite('default')
                    ->withPaths(__DIR__ . '/test/e2e/features')
                    ->withContexts(HttpContext::class, ManagementContext::class, SignInContext::class, RefreshContext::class, MailContext::class, AccountContext::class),
            ),
    );
