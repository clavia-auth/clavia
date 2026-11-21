<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Connection;

use Clavia\Domain\Shared\InvalidValue;
use DateTimeImmutable;

/**
 * A way to sign in — what Auth0 calls a connection: a pool of accounts with passwords,
 * Google, GitHub, an OpenID Connect provider.
 *
 * An application signs people in through the connections enabled for it and no others:
 * its login page shows only those, and a session established through any other does
 * not count for it. Two switches on every connection:
 *
 * - `isEnabled`, the global one: off, and no application can use it, whatever its own
 *   list says;
 * - `isDomainConnection`: open to every *third-party* application, which can use no
 *   other kind. A stranger's application does not pick its way in; it gets what the
 *   operator opened to strangers. A first-party application goes by its own list
 *   alone, so opening a connection to strangers forces it on no application of ours.
 *
 * Every account belongs to exactly one connection: the pool it was created in, or the
 * external connection that created it.
 */
final readonly class Connection
{
    private const int MAX_DISPLAY_NAME_LENGTH = 120;

    private function __construct(
        public ConnectionName $name,
        public string $displayName,
        public ConnectionStrategy $strategy,
        public bool $isEnabled,
        public bool $isDomainConnection,
        public ?OidcSettings $oidc,
        public DateTimeImmutable $createdAt,
    ) {
    }

    /**
     * A new pool of accounts with passwords.
     *
     * @throws InvalidValue When the display name is blank, longer than 120 characters or not one line.
     */
    public static function pool(
        ConnectionName $name,
        string $displayName,
        bool $isEnabled,
        bool $isDomainConnection,
        DateTimeImmutable $now,
    ): self {
        return self::reconstitute(
            $name,
            $displayName,
            ConnectionStrategy::Database,
            $isEnabled,
            $isDomainConnection,
            null,
            $now,
        );
    }

    /**
     * A new OpenID Connect provider.
     *
     * @throws InvalidValue
     */
    public static function openIdProvider(
        ConnectionName $name,
        string $displayName,
        OidcSettings $oidc,
        bool $isEnabled,
        bool $isDomainConnection,
        DateTimeImmutable $now,
    ): self {
        return self::reconstitute(
            $name,
            $displayName,
            ConnectionStrategy::Oidc,
            $isEnabled,
            $isDomainConnection,
            $oidc,
            $now,
        );
    }

    /**
     * A connection read back from storage — or seeded, for the built-in ones. The same
     * rules apply.
     *
     * @throws InvalidValue When the display name is unusable, or the OIDC settings are present
     *                      on anything but an OIDC connection or missing from one.
     */
    public static function reconstitute(
        ConnectionName $name,
        string $displayName,
        ConnectionStrategy $strategy,
        bool $isEnabled,
        bool $isDomainConnection,
        ?OidcSettings $oidc,
        DateTimeImmutable $createdAt,
    ): self {
        self::checkDisplayName($displayName);
        if (($strategy === ConnectionStrategy::Oidc) !== ($oidc !== null)) {
            throw new InvalidValue('An OIDC connection, and only one, has OIDC settings.');
        }

        return new self($name, $displayName, $strategy, $isEnabled, $isDomainConnection, $oidc, $createdAt);
    }

    /**
     * The same connection with its switches and its label changed; null leaves one as it is.
     *
     * Turning one off takes effect at the next sign-in: sessions established through it
     * stand until they end.
     *
     * @throws InvalidValue
     */
    public function switched(?bool $isEnabled, ?bool $isDomainConnection, ?string $displayName): self
    {
        return self::reconstitute(
            $this->name,
            $displayName ?? $this->displayName,
            $this->strategy,
            $isEnabled ?? $this->isEnabled,
            $isDomainConnection ?? $this->isDomainConnection,
            $this->oidc,
            $this->createdAt,
        );
    }

    /**
     * The same OIDC connection pointed at new provider settings.
     *
     * @throws InvalidValue When this is not an OIDC connection.
     */
    public function withOidc(OidcSettings $oidc): self
    {
        if ($this->strategy !== ConnectionStrategy::Oidc) {
            throw new InvalidValue('Only an OIDC connection has OIDC settings.');
        }

        return self::reconstitute(
            $this->name,
            $this->displayName,
            $this->strategy,
            $this->isEnabled,
            $this->isDomainConnection,
            $oidc,
            $this->createdAt,
        );
    }

    /**
     * Whether it may be deleted at all — leaving aside the accounts and identities that
     * depend on it, which the caller checks.
     *
     * @throws BuiltInConnection When it is a social connection or the default pool: the code's,
     *                           switched off rather than deleted.
     */
    public function assertDeletable(): void
    {
        if ($this->isBuiltIn()) {
            throw BuiltInConnection::deletion($this);
        }
    }

    /** Part of the code's catalogue — switchable, never created or deleted. */
    public function isBuiltIn(): bool
    {
        return $this->strategy === ConnectionStrategy::Social
            || $this->name->value === ConnectionName::DEFAULT_POOL;
    }

    public function isDatabase(): bool
    {
        return $this->strategy === ConnectionStrategy::Database;
    }

    /** Signs people in at another party — social or OIDC — rather than here. */
    public function isExternal(): bool
    {
        return $this->strategy->isExternal();
    }

    /**
     * @throws InvalidValue
     */
    private static function checkDisplayName(string $displayName): void
    {
        if (
            ! mb_check_encoding($displayName, 'UTF-8')
            || trim($displayName) === ''
            || mb_strlen($displayName, 'UTF-8') > self::MAX_DISPLAY_NAME_LENGTH
            || preg_match('/[\x00-\x1F\x7F]/', $displayName) === 1
        ) {
            throw new InvalidValue('A connection display name is one line of 1 to 120 characters.');
        }
    }
}
