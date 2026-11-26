<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication;

use Clavia\Application\Port\ConsentStateStore;
use Clavia\Application\Port\LoginStateStore;
use Clavia\Application\Port\MfaChallengeStore;

/**
 * The authorization request a page serves (docs/design/translated-sign-in-pages.md §5.2, and #25): whatever
 * holds it, a login state or a pending consent by the handle the page carries, or the second-factor
 * challenge its cookie names. Its languages choose the page's language; its application, the page's look.
 * Read only: nothing is claimed, and a handle that is unknown, spent or someone else's holds nothing.
 */
final readonly class HeldRequests
{
    public function __construct(
        private LoginStateStore $loginStates,
        private ConsentStateStore $consentStates,
        private MfaChallengeStore $challenges,
    ) {
    }

    /**
     * @param string|null $handle    A login state's or a pending consent's handle, as the page carries it.
     * @param string|null $challenge The second-factor challenge's handle, from its cookie.
     */
    public function __invoke(
        #[\SensitiveParameter] ?string $handle,
        #[\SensitiveParameter] ?string $challenge,
    ): HeldRequest {
        if ($handle !== null && $handle !== '') {
            $state = $this->loginStates->get($handle);
            if ($state !== null) {
                return new HeldRequest($state->uiLocales, $state->clientId);
            }
            $consent = $this->consentStates->find($handle);
            if ($consent !== null) {
                return new HeldRequest($consent->uiLocales, $consent->clientId, $consent->userId);
            }
        }
        if ($challenge !== null && $challenge !== '') {
            $pending = $this->challenges->find($challenge);
            if ($pending !== null) {
                return new HeldRequest($pending->uiLocales, $pending->clientId);
            }
        }

        return HeldRequest::none();
    }
}
