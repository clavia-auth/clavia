<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Claims;

use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\Url;

/**
 * The name of a custom claim: a public name, an https URI (RFC 7519 §4.2), or a private name
 * (§4.3), 1 to 64 of `[A-Za-z0-9_.-]`. Never a reserved name ({@see RESERVED}): a mapping that
 * could set `sub`, `aud` or `acr` would forge what the token means, and one that could set
 * `email` would let a typo make a relying party trust an address nobody verified
 * (docs/design/custom-claims.md §2).
 */
final readonly class ClaimName
{
    public const int MAX_PLAIN_LENGTH = 64;
    public const int MAX_URI_LENGTH = 255;

    private const string PLAIN = '/^[A-Za-z0-9_.-]{1,64}$/D';

    /**
     * Names a mapping never produces: the IANA "JSON Web Token Claims" registry (a snapshot,
     * November 2026), the OpenID Connect Core §5.1 standard claims, RFC 7662 §2.2's introspection
     * members, and this server's own. Kept as a list, not a lookup table, so nothing is read back
     * from a key.
     */
    public const array RESERVED = [
        // RFC 7519 §4.1
        'iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti',
        // OpenID Connect Core §2 and §5.1, and the registry's other OpenID entries
        'name', 'given_name', 'family_name', 'middle_name', 'nickname', 'preferred_username', 'profile',
        'picture', 'website', 'email', 'email_verified', 'gender', 'birthdate', 'zoneinfo', 'locale',
        'phone_number', 'phone_number_verified', 'address', 'updated_at', 'azp', 'nonce', 'auth_time',
        'at_hash', 'c_hash', 'acr', 'amr', 'sub_jwk', 'sid', '_claim_names', '_claim_sources',
        'verified_claims', 'place_of_birth', 'nationalities', 'birth_family_name', 'birth_given_name',
        'birth_middle_name', 'salutation', 'title', 'msisdn', 'also_known_as',
        // OAuth: RFC 7800, 8693, 9068, 9396, 9449, 8417 and the registry's other OAuth entries
        'cnf', 'act', 'scope', 'client_id', 'may_act', 'roles', 'groups', 'entitlements',
        'authorization_details', 'htm', 'htu', 'ath', 'events', 'toe', 'txn', 'rph', 'sub_id',
        'token_introspection', 'ace_profile', 'cnonce', 'exi',
        // SIP, STIR/PASSporT, vectors of trust, CDNI, EAT and others the registry lists
        'sip_from_tag', 'sip_date', 'sip_callid', 'sip_cseq_num', 'sip_via_branch', 'orig', 'dest', 'mky',
        'vot', 'vtm', 'attest', 'origid', 'jcard', 'at_use_nbr', 'div', 'opt', 'vc', 'vp', 'sph', 'rcd',
        'rcdi', 'crn', 'msgi', 'cdniv', 'cdnicrit', 'cdniip', 'cdniuc', 'cdniets', 'cdnistt', 'cdnistd',
        'sig_val_claims', 'eat_nonce', 'ueid', 'sueids', 'oemid', 'hwmodel', 'hwversion', 'swname',
        'swversion', 'oemboot', 'dbgstat', 'location', 'eat_profile', 'submods', 'uptime', 'bootcount',
        'bootseed', 'dloas', 'manifests', 'measurements', 'measres', 'intuse', 'geohash', 'wlg',
        'rdap_allowed_purposes', 'rdap_dnt_allowed',
        // RFC 7662 §2.2, which an introspection answer carries beside the claims
        'active', 'username', 'token_type',
        // This server's own
        'permissions', 'typ',
    ];

    /** RFC 9068 §2.2.3.1 defines it for access tokens: allowed on an API, from the roles source. */
    public const string ROLES = 'roles';

    /** @param non-empty-string $value */
    private function __construct(public string $value)
    {
    }

    /**
     * A name as an operator writes it.
     *
     * @param bool $onAnApi `roles` is allowed only for an API's access tokens.
     *
     * @throws InvalidValue
     */
    public static function fromString(string $name, bool $onAnApi): self
    {
        $claim = self::shaped($name);
        if ($claim->isReserved() && ! ($onAnApi && $name === self::ROLES)) {
            throw new InvalidValue('That claim name is reserved: the protocol or this server defines it.');
        }

        return $claim;
    }

    /**
     * A name as storage holds it: shaped, but not refused for being reserved, so a mapping saved
     * before a name joined the list still loads; {@see CustomClaims} refuses it at issuance.
     *
     * @throws InvalidValue
     */
    public static function fromStorage(string $name): self
    {
        return self::shaped($name);
    }

    public function isReserved(): bool
    {
        return in_array($this->value, self::RESERVED, true);
    }

    /** @throws InvalidValue */
    private static function shaped(string $name): self
    {
        if ($name === '') {
            throw new InvalidValue('A claim name is not empty.');
        }
        if (preg_match(self::PLAIN, $name) === 1) {
            return new self($name);
        }
        if (str_starts_with($name, 'https://') && strlen($name) <= self::MAX_URI_LENGTH) {
            try {
                $uri = Url::fromString($name);
            } catch (InvalidValue) {
                $uri = null;
            }
            if ($uri !== null && $uri->isHttps() && ! $uri->hasFragment()) {
                return new self($name);
            }
        }

        throw new InvalidValue(sprintf(
            'A claim name is an https URI of at most %d characters, or 1 to %d letters, digits, ".", "_" or "-".',
            self::MAX_URI_LENGTH,
            self::MAX_PLAIN_LENGTH,
        ));
    }
}
