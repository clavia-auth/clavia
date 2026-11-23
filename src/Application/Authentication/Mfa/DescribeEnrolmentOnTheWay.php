<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\Mfa;

use Clavia\Application\Port\LoginStateStore;
use Clavia\Domain\Authentication\LocalPath;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Shared\InvalidValue;

/**
 * The held request an enrolment page came from, if its handle is live: to say who asks for a
 * second factor, and — {@see self::resume()} — to go back to it once one is set up.
 */
final readonly class DescribeEnrolmentOnTheWay
{
    public function __construct(
        private LoginStateStore $loginStates,
        private ClientRepository $clients,
    ) {
    }

    /** Null for no handle, or one that is unknown, spent or expired. */
    public function __invoke(#[\SensitiveParameter] ?string $loginState): ?EnrolmentOnTheWay
    {
        $held = $loginState === null || $loginState === '' ? null : $this->loginStates->get($loginState);
        if ($loginState === null || $loginState === '' || $held === null) {
            return null;
        }
        $client = $held->clientId === null ? null : $this->clients->find($held->clientId);

        return new EnrolmentOnTheWay($loginState, $client?->name, $client?->redirectOrigins() ?? []);
    }

    /**
     * Where to send the browser back to: the held request, claimed so the handle works once, and
     * validated again as a local path. Null when there is nothing to go back to.
     */
    public function resume(#[\SensitiveParameter] ?string $loginState): ?string
    {
        $held = $loginState === null || $loginState === '' ? null : $this->loginStates->get($loginState);
        if ($loginState === null || $loginState === '' || $held === null) {
            return null;
        }
        $this->loginStates->forget($loginState);

        try {
            return LocalPath::fromString($held->nextUrl)->value;
        } catch (InvalidValue) {
            return null;
        }
    }
}
