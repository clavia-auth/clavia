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
use Clavia\Domain\OAuth2\UiLocales;

/**
 * The languages the request a page serves asked for (`ui_locales`, docs/design/
 * translated-sign-in-pages.md §5.2): whatever holds that request, a login state or a pending consent by
 * the handle the page carries, or the second-factor challenge its cookie names. Read only: nothing is
 * claimed, and a handle that is unknown, spent or someone else's simply holds no languages.
 */
final readonly class HeldLanguages
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
    ): UiLocales {
        if ($handle !== null && $handle !== '') {
            $held = $this->loginStates->get($handle)?->uiLocales ?? $this->consentStates->find($handle)?->uiLocales;
            if ($held !== null && ! $held->isEmpty()) {
                return $held;
            }
        }
        if ($challenge !== null && $challenge !== '') {
            return $this->challenges->find($challenge)?->uiLocales ?? UiLocales::none();
        }

        return UiLocales::none();
    }
}
