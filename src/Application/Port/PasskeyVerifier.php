<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Port;

use Clavia\Domain\Authentication\Passkey\CredentialId;
use Clavia\Domain\Authentication\Passkey\Passkey;
use Clavia\Domain\Authentication\Passkey\RelyingParty;
use Clavia\Domain\Authentication\Passkey\WebAuthnChallenge;

/**
 * Checks what a browser sends back from a WebAuthn ceremony (WebAuthn Level 3 §7): the one place
 * that knows CBOR, COSE keys, authenticator data and signature formats.
 *
 * The use cases build the options they send the browser, since the domain knows what to offer,
 * and hand this only the raw response, the challenge they sent and the relying party. The
 * challenge says what the ceremony was for, and so what to require of it: a registration and a
 * sign-in need the person verified, a second factor needs only presence, and a sign-in names
 * its passkey by the response while the other two know the account already.
 *
 * Attestation is `none`: the credential is accepted for what it is, and its maker (the AAGUID)
 * only labels it.
 */
interface PasskeyVerifier
{
    /**
     * The id of the credential a response is about, so the passkey can be looked up before the
     * response is verified against it. Not a verification: it trusts nothing in the response.
     *
     * @throws PasskeyRejected When the response is not a WebAuthn credential at all.
     */
    public function credentialIdOf(string $responseJson): CredentialId;

    /**
     * Verify the response to a registration (`navigator.credentials.create()`), as serialised by
     * the browser's `toJSON()`.
     *
     * @throws PasskeyRejected
     */
    public function verifyRegistration(
        string $responseJson,
        WebAuthnChallenge $challenge,
        RelyingParty $relyingParty,
    ): VerifiedRegistration;

    /**
     * Verify the response to an authentication (`navigator.credentials.get()`) against the
     * passkey it names.
     *
     * When the challenge identifies the account first, the passkey must be that account's;
     * otherwise the response must name the passkey's owner by its user handle.
     *
     * @throws PasskeyRejected
     */
    public function verifyAssertion(
        string $responseJson,
        WebAuthnChallenge $challenge,
        RelyingParty $relyingParty,
        Passkey $passkey,
    ): VerifiedAssertion;
}
