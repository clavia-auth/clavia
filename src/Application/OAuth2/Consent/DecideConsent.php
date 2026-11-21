<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\OAuth2\Consent;

use Clavia\Application\Authentication\EndUser;
use Clavia\Application\OAuth2\Authorize\RequestRefused;
use Clavia\Domain\Authentication\LocalPath;
use Clavia\Domain\Consent\ConsentRepository;
use Clavia\Domain\Consent\UserConsent;
use Clavia\Domain\OAuth2\OAuth2Error;
use Clavia\Domain\Shared\Clock;
use Clavia\Domain\Shared\InvalidValue;

/**
 * `POST /auth/consent`: the person's answer, given once.
 *
 * - **Allow** records the consent — widening one already held — and sends the browser
 *   back to the authorization request, which then finds it and issues the code. Going
 *   back rather than issuing here re-checks everything the request depends on, as it is
 *   at that moment.
 * - **Refuse** sends the browser to the application with `access_denied`
 *   (RFC 6749 §4.1.2.1): the person has to end up somewhere, and this is the outcome the
 *   protocol names for it. Nothing is recorded: being asked again is the right default.
 */
final readonly class DecideConsent
{
    public function __construct(
        private HeldConsents $held,
        private ConsentRepository $consents,
        private Clock $clock,
    ) {
    }

    /**
     * @return ConsentGiven|RequestRefused|null Null when the handle stands for nothing the signed-in
     *                                          person may decide — or was decided already.
     */
    public function __invoke(
        #[\SensitiveParameter] string $handle,
        EndUser $endUser,
        bool $allow,
    ): ConsentGiven|RequestRefused|null {
        $held = $this->held->find($handle, $endUser);
        if ($held === null || ! $this->held->release($handle)) {
            return null;
        }
        $pending = $held->pending;

        if (! $allow) {
            return new RequestRefused(
                $pending->redirectUri,
                OAuth2Error::accessDenied('The user did not allow the application to proceed.'),
                $pending->state,
            );
        }

        try {
            // Built by the authorization endpoint, and still checked: nothing read back
            // becomes a `Location` without it.
            $resumeAt = LocalPath::fromString($pending->resumeAt);
        } catch (InvalidValue) {
            return null;
        }

        $now = $this->clock->now();
        $given = $this->consents->find($pending->userId, $pending->clientId, $pending->resourceServerId);
        $this->consents->save($given?->widenedBy($pending->scope, $now) ?? UserConsent::give(
            $pending->userId,
            $pending->clientId,
            $pending->resourceServerId,
            $pending->scope,
            $now,
        ));

        return new ConsentGiven($resumeAt->value);
    }
}
