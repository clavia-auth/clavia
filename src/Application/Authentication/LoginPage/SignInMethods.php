<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\LoginPage;

use Clavia\Application\Authentication\External\ExternalProviderOption;

/**
 * The ways the login page offers to sign in, for the application it is shown for.
 */
final readonly class SignInMethods
{
    /**
     * @param bool                         $password  Whether the password form is shown: the application
     *                                                signs people in from at least one pool.
     * @param bool                         $email     Whether the email form is shown: the application signs
     *                                                people in with a code or a link sent by email.
     * @param list<ExternalProviderOption> $providers The external connections, in order.
     */
    public function __construct(
        public bool $password,
        public bool $email,
        public array $providers,
    ) {
    }

    /** No way in at all. */
    public static function none(): self
    {
        return new self(false, false, []);
    }

    /** Whether there is no way in at all — the page says so instead of showing an empty form. */
    public function isEmpty(): bool
    {
        return ! $this->password && ! $this->email && $this->providers === [];
    }
}
