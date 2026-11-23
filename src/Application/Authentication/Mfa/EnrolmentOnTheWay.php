<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\Mfa;

/**
 * What the enrolment pages say when a request requiring more than one factor sent the person
 * there (docs/design/mfa-policies.md §5.3): who asks, and where the forms that lead back to the
 * request may end — the application's redirect origins, for the pages' `form-action`.
 */
final readonly class EnrolmentOnTheWay
{
    /**
     * @param non-empty-string $loginState  The handle of the held request.
     * @param string|null      $application The application's name, when the request names one.
     * @param list<string>     $formOrigins
     */
    public function __construct(
        public string $loginState,
        public ?string $application,
        public array $formOrigins,
    ) {
    }
}
