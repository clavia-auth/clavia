<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\Passkey;

use Clavia\Domain\Authentication\Passkey\Passkey;
use Clavia\Domain\Authentication\Passkey\RelyingParty;
use Clavia\Domain\Authentication\Passkey\WebAuthnChallenge;

/**
 * What the browser needs to use a passkey (WebAuthn Level 3 §5.5), and the handle of the
 * ceremony it answers. The primary adapter writes it as `PublicKeyCredentialRequestOptionsJSON`.
 *
 * As a second factor the account is known, so its passkeys are named (`allowCredentials`), and
 * user verification is preferred, not required: the password came first.
 */
final readonly class AssertionOptions
{
    /**
     * @param non-empty-string $handle         The ceremony's handle, for the browser's cookie.
     * @param list<Passkey>    $allow          The passkeys that may answer.
     * @param positive-int     $timeoutSeconds
     */
    public function __construct(
        public string $handle,
        public RelyingParty $relyingParty,
        public WebAuthnChallenge $challenge,
        public array $allow,
        public int $timeoutSeconds,
    ) {
    }

    public function requiresUserVerification(): bool
    {
        return $this->challenge->purpose->requiresUserVerification();
    }
}
