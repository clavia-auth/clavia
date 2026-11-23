<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\ResourceServer;

use Clavia\Domain\Authentication\MfaPolicy;
use Clavia\Domain\Shared\Audience;
use Clavia\Domain\Shared\InvalidValue;
use Clavia\Domain\Shared\Scope;
use Clavia\Domain\Shared\ScopeSet;
use DateTimeImmutable;

/**
 * An API that accepts tokens issued by this server — what RFC 6749 §1.1 calls a
 * resource server and Auth0 an "API".
 *
 * Registering one is what makes a scope mean anything. Its `identifier` is the
 * `audience` a client names to get a token for it and the `aud` that token carries:
 * an identifier somebody owns, never dereferenced, and immutable — changing it would
 * invalidate every token already issued for the API.
 *
 * A client holds no scope of its own. Acting as itself, what it may take from an API
 * is its {@see ClientGrant} there, narrowed to what the API still defines. On someone's
 * behalf, it is what the API defines — or, when the API enforces roles, what that
 * person's roles grant there.
 */
final readonly class ResourceServer
{
    public const int MAX_IDENTIFIER_LENGTH = 255;

    private const int MAX_NAME_LENGTH = 120;

    /**
     * @param list<Permission> $permissions Unique by value, sorted by value.
     */
    private function __construct(
        public ResourceServerId $id,
        public Audience $identifier,
        public string $name,
        public array $permissions,
        public DateTimeImmutable $createdAt,
        public bool $isSystem,
        public bool $enforcePolicies,
        public bool $allowSkippingConsent,
        public AccessTokenFormat $accessTokenFormat,
        public MfaPolicy $mfaPolicy,
    ) {
    }

    /**
     * Register an API, or rebuild one from storage: the same rules apply to both.
     *
     * @param list<Permission> $permissions
     * @param bool             $isSystem        An API this server itself depends on — the Management API.
     *                                          Its permissions are the server's to define and it cannot be
     *                                          deleted: either would revoke the credentials needed to undo
     *                                          the mistake. Only provisioning on the machine sets it.
     * @param bool             $enforcePolicies Whether a token issued on a person's behalf carries only what
     *                                          their roles grant here, and is refused to somebody holding
     *                                          nothing. Always on for a system API: what an operator may do
     *                                          there has to depend on who they are.
     * @param bool             $allowSkippingConsent Whether a first-party application asking for these
     *                                               permissions on a person's behalf may do without the
     *                                               consent screen: the operator runs both, so signing in
     *                                               is the consent. A third-party application asks
     *                                               whatever this says. Always on for a system API, which
     *                                               no third-party application can reach.
     * @param AccessTokenFormat $accessTokenFormat Opaque, checked by introspection, or a JWT the API
     *                                             validates on its own (RFC 9068).
     * @param MfaPolicy         $mfaPolicy         Whether a person must sign in with more than one factor
     *                                             to be issued a token for it.
     *
     * @throws InvalidValue When the identifier is longer than 255 bytes, the name longer than
     *                      120 characters, a permission is defined twice, or a system API would
     *                      not enforce roles or would ask for consent.
     */
    public static function register(
        ResourceServerId $id,
        Audience $identifier,
        string $name,
        array $permissions,
        DateTimeImmutable $createdAt,
        bool $isSystem = false,
        bool $enforcePolicies = false,
        bool $allowSkippingConsent = true,
        AccessTokenFormat $accessTokenFormat = AccessTokenFormat::Opaque,
        MfaPolicy $mfaPolicy = MfaPolicy::Optional,
    ): self {
        if (strlen($identifier->value) > self::MAX_IDENTIFIER_LENGTH) {
            throw new InvalidValue('An API identifier is at most 255 bytes.');
        }
        if (! mb_check_encoding($name, 'UTF-8') || mb_strlen($name, 'UTF-8') > self::MAX_NAME_LENGTH) {
            throw new InvalidValue('An API name is at most 120 characters.');
        }
        if ($isSystem && ! $enforcePolicies) {
            throw new InvalidValue('A system API always enforces roles.');
        }
        if ($isSystem && ! $allowSkippingConsent) {
            throw new InvalidValue('A system API never asks for consent: only first-party applications reach it.');
        }

        $byValue = [];
        foreach ($permissions as $permission) {
            // Keyed for lookup only; the value is read back from the permission itself.
            $key = 'p:' . $permission->value->value;
            if (isset($byValue[$key])) {
                throw new InvalidValue(sprintf("The permission '%s' is defined twice.", $permission->value->value));
            }
            $byValue[$key] = $permission;
        }
        $sorted = array_values($byValue);
        usort($sorted, static fn (Permission $a, Permission $b): int => strcmp($a->value->value, $b->value->value));

        return new self(
            $id,
            $identifier,
            $name,
            $sorted,
            $createdAt,
            $isSystem,
            $enforcePolicies,
            $allowSkippingConsent,
            $accessTokenFormat,
            $mfaPolicy,
        );
    }

    /**
     * The same API under another name. Allowed for a system API too: a name is a label.
     *
     * @throws InvalidValue When the name is longer than 120 characters.
     */
    public function renamed(string $name): self
    {
        return self::register(
            $this->id,
            $this->identifier,
            $name,
            $this->permissions,
            $this->createdAt,
            $this->isSystem,
            $this->enforcePolicies,
            $this->allowSkippingConsent,
            $this->accessTokenFormat,
            $this->mfaPolicy,
        );
    }

    /**
     * The same API, enforcing roles or not.
     *
     * Refused for a system API: turning roles off there would hand every permission it
     * defines to anybody who can sign in.
     *
     * @throws SystemApiProtected
     */
    public function enforcingPolicies(bool $enforce): self
    {
        if ($this->isSystem && ! $enforce) {
            throw SystemApiProtected::policies($this);
        }

        return new self(
            $this->id,
            $this->identifier,
            $this->name,
            $this->permissions,
            $this->createdAt,
            $this->isSystem,
            $enforce,
            $this->allowSkippingConsent,
            $this->accessTokenFormat,
            $this->mfaPolicy,
        );
    }

    /**
     * The same API, letting first-party applications do without the consent screen for
     * its permissions or not.
     *
     * Refused for a system API: only first-party applications ever reach one, and they are
     * the operator's own — there is nobody to ask about.
     *
     * @throws SystemApiProtected
     */
    public function allowingConsentSkip(bool $allow): self
    {
        if ($this->isSystem && ! $allow) {
            throw SystemApiProtected::consent($this);
        }

        return new self(
            $this->id,
            $this->identifier,
            $this->name,
            $this->permissions,
            $this->createdAt,
            $this->isSystem,
            $this->enforcePolicies,
            $allow,
            $this->accessTokenFormat,
            $this->mfaPolicy,
        );
    }

    /**
     * The same API defining exactly `$permissions`.
     *
     * Refused for a system API: its permissions are demanded by name by the server's
     * own routes, so removing one would leave a permission nobody can be granted —
     * including whoever would need it to put it back.
     *
     * @param list<Permission> $permissions
     *
     * @throws SystemApiProtected
     * @throws InvalidValue When a permission is defined twice.
     */
    public function withPermissions(array $permissions): self
    {
        if ($this->isSystem) {
            throw SystemApiProtected::permissions($this);
        }

        return self::register(
            $this->id,
            $this->identifier,
            $this->name,
            $permissions,
            $this->createdAt,
            false,
            $this->enforcePolicies,
            $this->allowSkippingConsent,
            $this->accessTokenFormat,
            $this->mfaPolicy,
        );
    }

    /**
     * The same API, marked as one the server depends on — enforcing roles and never asking
     * for consent, as a system API always does — defining exactly `$permissions`. For
     * provisioning on the machine only.
     *
     * @param list<Permission> $permissions
     *
     * @throws InvalidValue
     */
    public function asSystem(string $name, array $permissions): self
    {
        return self::register(
            $this->id,
            $this->identifier,
            $name,
            $permissions,
            $this->createdAt,
            true,
            true,
            true,
            $this->accessTokenFormat,
            $this->mfaPolicy,
        );
    }

    /**
     * The same API, issued access tokens of `$format` from the next token on. Tokens
     * already issued keep the form they were issued in. Allowed for a system API too: the
     * form is a matter between this server and the API, and either is checked here alike.
     */
    public function issuingAccessTokensAs(AccessTokenFormat $format): self
    {
        return new self(
            $this->id,
            $this->identifier,
            $this->name,
            $this->permissions,
            $this->createdAt,
            $this->isSystem,
            $this->enforcePolicies,
            $this->allowSkippingConsent,
            $format,
            $this->mfaPolicy,
        );
    }

    /**
     * The same API, taking people in on one factor or not, from the next authorization on.
     * Allowed for a system API too: requiring more of its operators only narrows who gets in.
     */
    public function requiringMfa(MfaPolicy $policy): self
    {
        return new self(
            $this->id,
            $this->identifier,
            $this->name,
            $this->permissions,
            $this->createdAt,
            $this->isSystem,
            $this->enforcePolicies,
            $this->allowSkippingConsent,
            $this->accessTokenFormat,
            $policy,
        );
    }

    /**
     * @throws SystemApiProtected When the API is a system API.
     */
    public function assertDeletable(): void
    {
        if ($this->isSystem) {
            throw SystemApiProtected::deletion($this);
        }
    }

    /** Whether this API defines `$scope` as one of its permissions. */
    public function defines(Scope|string $scope): bool
    {
        $value = $scope instanceof Scope ? $scope->value : $scope;

        return array_any(
            $this->permissions,
            static fn (Permission $permission): bool => $permission->value->value === $value,
        );
    }

    /** Every permission this API defines, as a scope. */
    public function permissionScopes(): ScopeSet
    {
        return ScopeSet::of(
            ...array_map(static fn (Permission $permission): Scope => $permission->value, $this->permissions),
        );
    }
}
