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
use Clavia\Domain\Authentication\OneTimeCode;
use Clavia\Domain\Shared\InvalidValue;

/**
 * Check a typed code against the challenge of the browser that asked for it.
 *
 * The challenge is found through the browser's own cookie, never through anything in the
 * form: a code read over someone's shoulder, or forwarded, answers nothing in another
 * browser. Six digits are guessable, so every wrong answer — a malformed one included —
 * spends one of `CLAVIA_PASSWORDLESS_MAX_ATTEMPTS`; the last one ends the challenge and
 * the code with it. A right answer claims the challenge, so the code signs in once.
 */
final readonly class AnswerPasswordlessCode
{
    /**
     * @param positive-int $maxAttempts
     */
    public function __construct(
        private PasswordlessChallengeStore $challenges,
        private DescribePasswordlessChallenge $describe,
        private FinishPasswordlessSignIn $finish,
        private int $maxAttempts,
    ) {
    }

    /**
     * @param string|null $handle           The challenge's handle, from the browser's cookie.
     * @param string|null $currentSessionId The session the browser already holds, if any.
     */
    public function __invoke(
        #[\SensitiveParameter] ?string $handle,
        #[\SensitiveParameter] string $typed,
        #[\SensitiveParameter] ?string $currentSessionId,
    ): SignedIn|SecondFactorRequired|PasswordlessCodeRejected|PasswordlessRefused {
        $challenge = $handle === null || $handle === '' ? null : $this->challenges->find($handle);
        if ($handle === null || $handle === '' || $challenge === null || ! $challenge->isCode()) {
            return new PasswordlessRefused(PasswordlessFailure::Expired);
        }

        try {
            $accepted = $challenge->acceptsCode($handle, OneTimeCode::fromTyped($typed));
        } catch (InvalidValue) {
            $accepted = false;
        }
        if (! $accepted) {
            return $this->challenges->recordFailure($handle, $this->maxAttempts)
                ? new PasswordlessCodeRejected($this->describe->prompt($challenge))
                : new PasswordlessRefused(PasswordlessFailure::Expired);
        }

        // Of two right answers racing, one claims the challenge; the other finds it gone.
        $claimed = $this->challenges->claim($handle);
        if ($claimed === null) {
            return new PasswordlessRefused(PasswordlessFailure::Expired);
        }

        return ($this->finish)($claimed, $currentSessionId);
    }
}
