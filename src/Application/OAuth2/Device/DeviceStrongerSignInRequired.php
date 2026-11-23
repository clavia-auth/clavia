<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\OAuth2\Device;

/**
 * The device's application, or its API, requires more than one factor and the person signed in
 * with one (docs/design/mfa-policies.md §5.4). The request stays pending while they give another
 * factor (`$stepUp`) or set one up (`$enrolment`) and come back to the same code; with neither,
 * nothing they hold would do.
 */
final readonly class DeviceStrongerSignInRequired
{
    /**
     * @param non-empty-string|null $stepUp    A step-up challenge's handle, for the second-factor page.
     * @param non-empty-string|null $enrolment A login state's handle, for the enrolment page.
     */
    public function __construct(
        public ?string $stepUp,
        public ?string $enrolment,
    ) {
    }
}
