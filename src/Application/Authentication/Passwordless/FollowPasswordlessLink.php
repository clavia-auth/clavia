<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);


namespace Clavia\Application\Authentication\Passwordless;

use Clavia\Application\Authentication\SignIn\SecondFactorRequired;
use Clavia\Application\Authentication\SignIn\SignedIn;
use Clavia\Application\Port\PasswordlessChallengeStore;

/**
 * Spend a sign-in link, from the confirmation page it opened on.
 *
 * Never on the GET that opened it: mail scanners and link previewers fetch the URLs in an
 * email, and a link spent by a robot would be dead when the person clicks it — or, worse,
 * sign the robot in. The page asks; the POST from it lands here. Any browser may spend a
 * link: opening it on another device is what a link is for.
 *
 * Only a link's token works here. A code challenge's handle — the cookie of the browser
 * that asked for a code — is refused, or holding the cookie would sign in without the code.
 */
final readonly class FollowPasswordlessLink
{
    public function __construct(
        private PasswordlessChallengeStore $challenges,
        private FinishPasswordlessSignIn $finish,
    ) {
    }

    /**
     * @param string|null $token            The link's secret, from the confirmation form.
     * @param string|null $currentSessionId The session the browser already holds, if any.
     */
    public function __invoke(
        #[\SensitiveParameter] ?string $token,
        #[\SensitiveParameter] ?string $currentSessionId,
    ): SignedIn|SecondFactorRequired|PasswordlessRefused {
        if ($token === null || $token === '' || $this->challenges->find($token)?->isLink() !== true) {
            return new PasswordlessRefused(PasswordlessFailure::InvalidLink);
        }

        // Of two confirmations racing, one claims the link; the other finds it gone.
        $claimed = $this->challenges->claim($token);
        if ($claimed === null || ! $claimed->isLink()) {
            return new PasswordlessRefused(PasswordlessFailure::InvalidLink);
        }

        return ($this->finish)($claimed, $currentSessionId);
    }
}
