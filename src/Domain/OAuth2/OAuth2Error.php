<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\OAuth2;

use DomainException;

/**
 * The protocol says no.
 *
 * Carries the registered error code and a description written for the developer of the
 * client, never for an end user and never containing a secret. How the refusal travels —
 * a JSON body, a redirect back to the client, a `WWW-Authenticate` challenge — is the
 * primary adapter's business; which code applies is decided here, by the rule that was
 * broken.
 */
final class OAuth2Error extends DomainException
{
    /**
     * @param string|null $dpopNonce The nonce to send in `DPoP-Nonce` (RFC 9449 §8), for `use_dpop_nonce`.
     * @param string|null $reason    Why, for the log and never the client: a DPoP proof's refusal.
     */
    private function __construct(
        public readonly ErrorCode $error,
        public readonly string $description,
        public readonly ?string $dpopNonce = null,
        public readonly ?string $reason = null,
    ) {
        parent::__construct($error->value . ': ' . $description);
    }

    /** RFC 9449 §5: one answer, whatever was wrong with the proof; `$reason` is for the log. */
    public static function invalidDpopProof(string $reason): self
    {
        return new self(ErrorCode::InvalidDpopProof, 'The DPoP proof is not valid for this request.', null, $reason);
    }

    /** RFC 9449 §8: retry with this nonce in the proof. */
    public static function useDpopNonce(string $nonce): self
    {
        return new self(ErrorCode::UseDpopNonce, "The DPoP proof must carry the server's nonce.", $nonce);
    }

    public static function invalidRequest(string $description): self
    {
        return new self(ErrorCode::InvalidRequest, $description);
    }

    public static function invalidClient(string $description): self
    {
        return new self(ErrorCode::InvalidClient, $description);
    }

    public static function invalidGrant(string $description): self
    {
        return new self(ErrorCode::InvalidGrant, $description);
    }

    public static function unauthorizedClient(string $description): self
    {
        return new self(ErrorCode::UnauthorizedClient, $description);
    }

    public static function unsupportedGrantType(string $description): self
    {
        return new self(ErrorCode::UnsupportedGrantType, $description);
    }

    public static function unsupportedResponseType(string $description): self
    {
        return new self(ErrorCode::UnsupportedResponseType, $description);
    }

    public static function invalidScope(string $description): self
    {
        return new self(ErrorCode::InvalidScope, $description);
    }

    public static function invalidTarget(string $description): self
    {
        return new self(ErrorCode::InvalidTarget, $description);
    }

    public static function accessDenied(string $description): self
    {
        return new self(ErrorCode::AccessDenied, $description);
    }

    public static function loginRequired(string $description): self
    {
        return new self(ErrorCode::LoginRequired, $description);
    }

    public static function interactionRequired(string $description): self
    {
        return new self(ErrorCode::InteractionRequired, $description);
    }

    public static function unmetAuthenticationRequirements(string $description): self
    {
        return new self(ErrorCode::UnmetAuthenticationRequirements, $description);
    }

    public static function consentRequired(string $description): self
    {
        return new self(ErrorCode::ConsentRequired, $description);
    }

    public static function authorizationPending(string $description): self
    {
        return new self(ErrorCode::AuthorizationPending, $description);
    }

    public static function slowDown(string $description): self
    {
        return new self(ErrorCode::SlowDown, $description);
    }

    public static function expiredToken(string $description): self
    {
        return new self(ErrorCode::ExpiredToken, $description);
    }

    public static function unsupportedTokenType(string $description): self
    {
        return new self(ErrorCode::UnsupportedTokenType, $description);
    }

    public static function requestNotSupported(string $description): self
    {
        return new self(ErrorCode::RequestNotSupported, $description);
    }

    public static function requestUriNotSupported(string $description): self
    {
        return new self(ErrorCode::RequestUriNotSupported, $description);
    }
}
