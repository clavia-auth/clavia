<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\Mfa;

use Clavia\Application\Port\MfaChallengeStore;
use Clavia\Domain\Authentication\Mfa\MfaFactorRepository;
use Clavia\Domain\Authentication\Passkey\PasskeyRepository;
use Clavia\Domain\Client\ClientRepository;

/**
 * What the second-factor page needs: whether there is a challenge to answer at all, which
 * second factors the account can answer it with, and the origins the sign-in it finishes may
 * end at — the application's redirect origins, for the page's `form-action` (see the auth
 * pages' CSP).
 */
final readonly class DescribeSecondFactorPage
{
    public function __construct(
        private MfaChallengeStore $challenges,
        private ClientRepository $clients,
        private MfaFactorRepository $factors,
        private ?PasskeyRepository $passkeys,
    ) {
    }

    /**
     * Null when there is no challenge. The passkey repository is null when passkeys are off.
     */
    public function __invoke(#[\SensitiveParameter] ?string $challenge): ?SecondFactorPage
    {
        $pending = $challenge === null || $challenge === '' ? null : $this->challenges->find($challenge);
        if ($pending === null) {
            return null;
        }
        $client = $pending->clientId === null ? null : $this->clients->find($pending->clientId);

        return new SecondFactorPage(
            $client?->redirectOrigins() ?? [],
            $this->factors->find($pending->userId)?->isConfirmed() ?? false,
            ($this->passkeys?->countOf($pending->userId) ?? 0) > 0,
        );
    }
}
