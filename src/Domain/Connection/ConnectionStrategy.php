<?php

/**
 * This file is part of Clavia, an open-source OAuth 2.1 / OpenID Connect authorization server.
 *
 * @license   BSD-3-Clause — see the LICENSE file distributed with this source code.
 * @copyright Copyright (c) 2026 Phayne Limited. (https://phayne.io)
 */

declare(strict_types=1);

namespace Clavia\Domain\Connection;

/**
 * How a connection signs people in.
 */
enum ConnectionStrategy: string
{
    /** A pool of accounts with passwords, held by this server. Several may exist. */
    case Database = 'database';

    /**
     * One of the providers the code implements (Google, GitHub), its credentials from the
     * deployment's settings. Built in: switched on and off, never created or deleted.
     */
    case Social = 'social';

    /** Any OpenID Connect provider, registered by an operator from its issuer. */
    case Oidc = 'oidc';

    /**
     * Proof of control of a mailbox — a one-time code or a sign-in link sent by email —
     * standing in for a password. Built in, as the `email` connection: usable only while
     * the deployment can send mail.
     */
    case Passwordless = 'passwordless';

    /** A SAML 2.0 identity provider, registered by an operator from its metadata. */
    case Saml = 'saml';

    /**
     * Whether a directory may provision its accounts through SCIM (docs/design/scim-provisioning.md
     * §2): a pool, or an enterprise connection, whose staff the directory owns. A social provider's
     * accounts are the provider's, and passwordless has no account of its own to provision.
     */
    public function isProvisionable(): bool
    {
        return $this === self::Database || $this === self::Oidc || $this === self::Saml;
    }

    /** Signs people in at another party rather than here. */
    public function isExternal(): bool
    {
        return $this === self::Social || $this === self::Oidc || $this === self::Saml;
    }
}
