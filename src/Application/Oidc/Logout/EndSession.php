<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Application\Oidc\Logout;

use Clavia\Application\Authentication\Sessions;
use Clavia\Application\Port\SignatureVerifier;
use Clavia\Application\Port\TokenSigner;
use Clavia\Domain\Authentication\LocalPath;
use Clavia\Domain\Client\Client;
use Clavia\Domain\Client\ClientId;
use Clavia\Domain\Client\ClientRepository;
use Clavia\Domain\Shared\InvalidValue;

/**
 * The end-session endpoint: an application signs its person out of this server
 * (OpenID Connect RP-Initiated Logout 1.0).
 *
 * A request that ends a session can be forged from any page — a link, an `<img>` —
 * so the session ends at once only when `id_token_hint` proves the request: an ID
 * token this server signed (checked against the keys it publishes, retired ones
 * included), for this issuer, whose `sub` is the session's own person. Its expiry is
 * not checked (§2: the hint may have expired — someone leaving should not be stopped
 * by a five-minute token). Anything less, and the person is asked
 * ({@see SignOutConfirmationNeeded}); what they confirm on this server's own page is
 * the proof.
 *
 * Where the browser goes afterwards is a `post_logout_redirect_uri` the application
 * identified — by the hint's audience, or by `client_id`, which must then agree —
 * registered, and matched exactly (§3.1), with `state` appended. Anything else is
 * not followed: the browser stays on this server.
 */
final readonly class EndSession
{
    public function __construct(
        private Sessions $sessions,
        private ClientRepository $clients,
        private TokenSigner $keys,
        private SignatureVerifier $verifier,
        private string $issuer,
    ) {
    }

    public function __invoke(EndSessionRequest $request): SignedOut|SignOutConfirmationNeeded
    {
        $hint = $request->idTokenHint === null ? null : $this->claimsOf($request->idTokenHint);
        $client = $this->client($hint, $request->clientId);
        $destination = $client === false ? null : $this->destination($client, $request->postLogoutRedirectUri);
        /** @var mixed $subject */
        $subject = $hint['sub'] ?? null;
        // A hint that names another application than client_id proves nothing.
        $provenFor = $client === false || ! is_string($subject) ? null : $subject;

        $session = $this->sessions->resolve($request->sessionId);
        if ($session === null) {
            return new SignedOut($this->location($destination, $request->state), false);
        }

        if ($request->confirmed || $provenFor === $session->userId->value) {
            $this->sessions->end($request->sessionId);

            return new SignedOut($this->location($destination, $request->state), true);
        }

        return new SignOutConfirmationNeeded(
            $client instanceof Client ? $client->id->value : null,
            $client instanceof Client ? $client->name : null,
            $destination,
            $destination === null ? null : $request->state,
        );
    }

    /**
     * The hint's claims, when it is an ID token this server signed for this issuer.
     *
     * @return array<string, mixed>|null
     */
    private function claimsOf(string $idTokenHint): ?array
    {
        $claims = $this->verifier->verifiedClaims($idTokenHint, $this->keys->publicKeys());

        $ours = $claims !== null && ($claims['iss'] ?? null) === $this->issuer && is_string($claims['sub'] ?? null);

        return $ours ? $claims : null;
    }

    /**
     * The application the request is for: the hint's audience, or `client_id`. False when
     * the two disagree; null when neither names a registered client.
     *
     * @param array<string, mixed>|null $hint
     */
    private function client(?array $hint, ?string $clientId): Client|false|null
    {
        /** @var mixed $audience */
        $audience = $hint['aud'] ?? null;
        if (is_array($audience)) {
            // OIDC Core §2: several audiences name the one it was issued to in `azp`.
            /** @var mixed $audience */
            $audience = count($audience) === 1 ? reset($audience) : ($hint['azp'] ?? null);
        }
        $named = is_string($audience) ? $audience : null;

        if ($named !== null && $clientId !== null && $named !== $clientId) {
            return false;
        }

        $id = $named ?? $clientId;
        if ($id === null) {
            return null;
        }

        try {
            return $this->clients->find(ClientId::fromString($id));
        } catch (InvalidValue) {
            return null;
        }
    }

    private function destination(?Client $client, ?string $postLogoutRedirectUri): ?string
    {
        $registered = $client !== null
            && $postLogoutRedirectUri !== null
            && $client->hasPostLogoutRedirectUri($postLogoutRedirectUri);

        return $registered ? $postLogoutRedirectUri : null;
    }

    /** The registered URI with `state` added to its query (§3), or this server's login page. */
    private function location(?string $destination, ?string $state): string
    {
        if ($destination === null) {
            return LocalPath::DEFAULT;
        }
        if ($state === null) {
            return $destination;
        }

        return $destination . (str_contains($destination, '?') ? '&' : '?')
            . http_build_query(['state' => $state], '', '&', PHP_QUERY_RFC3986);
    }
}
