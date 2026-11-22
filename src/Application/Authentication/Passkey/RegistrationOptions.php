<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Authentication\Passkey;

use Clavia\Domain\Authentication\Passkey\CoseAlgorithm;
use Clavia\Domain\Authentication\Passkey\Passkey;
use Clavia\Domain\Authentication\Passkey\RelyingParty;
use Clavia\Domain\Authentication\Passkey\WebAuthnChallenge;

/**
 * What the browser needs to make a passkey (WebAuthn Level 3 §5.4), and the handle of the
 * ceremony it answers. The primary adapter writes it as `PublicKeyCredentialCreationOptionsJSON`.
 *
 * Decided here, not by the page: the account the passkey is for, by its user handle and never
 * by anything personal; the algorithms offered; the passkeys it already holds, so an
 * authenticator that has one says so; a discoverable credential with the person verified; no
 * attestation.
 */
final readonly class RegistrationOptions
{
    /**
     * @param non-empty-string $handle      The ceremony's handle, for the browser's cookie.
     * @param string           $userName    How the account is named to its owner: its address.
     * @param string           $displayName The account's name, or its address when it has none.
     * @param list<Passkey>    $exclude     The account's passkeys.
     * @param positive-int     $timeoutSeconds
     */
    public function __construct(
        public string $handle,
        public RelyingParty $relyingParty,
        public WebAuthnChallenge $challenge,
        public string $userName,
        public string $displayName,
        public array $exclude,
        public int $timeoutSeconds,
    ) {
    }

    /** @return list<CoseAlgorithm> Most preferred first. */
    public function algorithms(): array
    {
        return CoseAlgorithm::preferred();
    }
}
